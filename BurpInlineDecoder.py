# -*- coding: utf-8 -*-
# BurpInlineDecoder — Grep-Extract parity + inline decode (Intruder)
# Jython 2.7.x compatible

from burp import IBurpExtender, ITab, IHttpListener, IBurpExtenderCallbacks
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from javax.swing import (JPanel, JLabel, JTextField, JComboBox, JCheckBox,
                         JRadioButton, ButtonGroup)
from javax.swing.border import EmptyBorder
from java.awt.event import ItemListener
from javax.swing.event import DocumentListener
from java.util import WeakHashMap

import base64, binascii, zlib, json, re, urllib

__version__ = "1.0.1"  # fixes GridBagConstraints tuple-assign bug (Jython-safe)

# -------------------- helpers --------------------

def to_text(b):
    if isinstance(b, unicode):
        return b
    try:
        return b.decode("utf-8")
    except Exception:
        try:
            return b.decode("latin-1")
        except Exception:
            return unicode(repr(b))

def to_bytes(x):
    return x.encode("latin-1") if isinstance(x, unicode) else x

def b64pad(s):
    m = len(s) % 4
    return s + ("=" * (4 - m) if m else "")

def dec_b64(s):
    return base64.b64decode(b64pad(s))

def dec_b64url(s):
    return base64.urlsafe_b64decode(b64pad(s))

def dec_hex(s):
    s = re.sub(r"[^0-9A-Fa-f]", "", s)
    return binascii.unhexlify(s)

def url_decode_multipass(s, max_pass=3):
    prev = s
    for _ in range(max_pass):
        cur = urllib.unquote_plus(prev)
        if cur == prev:
            break
        prev = cur
    return prev

def inflate_try(b):
    b = to_bytes(b)
    if len(b) >= 2 and b[:2] == "\x1f\x8b":
        import gzip, StringIO
        bio = StringIO.StringIO(b)
        gf = gzip.GzipFile(fileobj=bio, mode='rb')
        try:
            return gf.read()
        finally:
            gf.close()
    for w in (15, -15):
        try:
            return zlib.decompress(b, wbits=w)
        except Exception:
            pass
    raise ValueError("Not gzip/deflate")

def jwt_decode(s):
    parts = s.split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT")
    hdr = to_text(dec_b64url(parts[0]))
    pld = to_text(dec_b64url(parts[1]))
    try:
        import json as _json
        hdr = _json.dumps(_json.loads(hdr), indent=2)
    except Exception:
        pass
    try:
        import json as _json
        pld = _json.dumps(_json.loads(pld), indent=2)
    except Exception:
        pass
    return u"[JWT header]\n%s\n\n[JWT payload]\n%s" % (hdr, pld)

def json_pretty(s):
    if not isinstance(s, basestring):
        s = to_text(s)
    return json.dumps(json.loads(s), indent=2, ensure_ascii=False)

DECODERS = [
    "Auto (Base64)",
    "Base64",
    "Base64 (URL-safe)",
    "Hex -> Text",
    "URL-decode",
    "Gzip/Deflate",
    "JWT header+payload",
    "JSON pretty",
]

def auto_b64(s):
    try:
        return dec_b64(s)
    except Exception:
        return dec_b64url(s)

DEC_FN = {
    "Auto (Base64)":      lambda s: auto_b64(s),
    "Base64":             lambda s: dec_b64(s),
    "Base64 (URL-safe)":  lambda s: dec_b64url(s),
    "Hex -> Text":        lambda s: dec_hex(s),
    "URL-decode":         lambda s: url_decode_multipass(s).encode("utf-8"),
    "Gzip/Deflate":       lambda s: inflate_try(s),
    "JWT header+payload": lambda s: jwt_decode(s).encode("utf-8"),
    "JSON pretty":        lambda s: json_pretty(s).encode("utf-8"),
}

def sanitize_for_decoder(s, decoder_name):
    t = s.strip().strip('"').strip("'")
    if decoder_name in ("Auto (Base64)", "Base64"):
        m = re.findall(r"[A-Za-z0-9+/=]+", t)
        if m:
            t = max(m, key=len)
        t = b64pad(t)
    elif decoder_name == "Base64 (URL-safe)":
        m = re.findall(r"[-A-Za-z0-9_=]+", t)
        if m:
            t = max(m, key=len)
        t = b64pad(t)
    elif decoder_name == "Hex -> Text":
        t = re.sub(r"[^0-9A-Fa-f]", "", t)
    return t

# Interpret \r \n \t \xHH typed by user in delimiter fields (literal bytes, not regex)
def unescape_literals(s):
    if s is None:
        return ""
    s = to_text(s)
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == '\\' and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == 'r':
                out.append(u'\r'); i += 2; continue
            if nxt == 'n':
                out.append(u'\n'); i += 2; continue
            if nxt == 't':
                out.append(u'\t'); i += 2; continue
            if nxt == 'x' and i + 3 < len(s):
                hex2 = s[i + 2:i + 4]
                try:
                    out.append(unichr(int(hex2, 16)))
                    i += 4; continue
                except Exception:
                    pass
        out.append(ch); i += 1
    return u"".join(out)

# -------------------- small listeners --------------------

class _DocSave(DocumentListener):
    def __init__(self, savefn):
        self._save = savefn
    def insertUpdate(self, e):
        self._save()
    def removeUpdate(self, e):
        self._save()
    def changedUpdate(self, e):
        self._save()

class _ItemSave(ItemListener):
    def __init__(self, savefn):
        self._save = savefn
    def itemStateChanged(self, e):
        self._save()

class _MutualToggle(ItemListener):
    def __init__(self, tab, who):
        self.tab, self.who = tab, who
    def itemStateChanged(self, e):
        if self.who == "regex":
            if self.tab.regexEnable.isSelected():
                self.tab.betweenEnable.setSelected(False)
        else:
            if self.tab.betweenEnable.isSelected():
                self.tab.regexEnable.setSelected(False)
        self.tab._syncModeEnable(); self.tab._saveSettings()

# -------------------- UI --------------------

class GrepXTab(JPanel, ITab):
    def __init__(self, callbacks):
        JPanel.__init__(self, BorderLayout())
        self.cb = callbacks
        self.setBorder(EmptyBorder(6, 6, 6, 6))

        # -- Between delimiters (parity with Grep-Extract) --
        self.betweenEnable = JCheckBox("Define start and end", True)

        # start choices
        self.startAfterRb = JRadioButton("Start after expression:", True)
        self.startAfterTf = JTextField("-Trial:", 28)
        self.startAtOffRb = JRadioButton("Start at offset:", False)
        self.startAtOffTf = JTextField("0", 6)
        self.startGroup = ButtonGroup()
        self.startGroup.add(self.startAfterRb)
        self.startGroup.add(self.startAtOffRb)

        # end choices
        self.endAtDelimRb = JRadioButton("End at delimiter:", True)
        self.endAtDelimTf = JTextField(r"\r\nOrigin-", 28)
        self.endFixedRb = JRadioButton("End at fixed length:", False)
        self.endFixedTf = JTextField("0", 6)
        self.endGroup = ButtonGroup()
        self.endGroup.add(self.endAtDelimRb)
        self.endGroup.add(self.endFixedRb)

        pBetween = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 6, 4, 6)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST

        # Row 0: start-after
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0
        pBetween.add(self.startAfterRb, gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        pBetween.add(self.startAfterTf, gbc)

        # Row 1: start-offset
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0
        pBetween.add(self.startAtOffRb, gbc)
        gbc.gridx = 1; gbc.weightx = 0.0
        pBetween.add(self.startAtOffTf, gbc)

        # Row 2: end-delim
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0
        pBetween.add(self.endAtDelimRb, gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        pBetween.add(self.endAtDelimTf, gbc)

        # Row 3: end-fixed
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0
        pBetween.add(self.endFixedRb, gbc)
        gbc.gridx = 1; gbc.weightx = 0.0
        pBetween.add(self.endFixedTf, gbc)

        betweenOuter = JPanel(BorderLayout())
        betweenOuter.add(self.betweenEnable, BorderLayout.NORTH)
        betweenOuter.add(pBetween, BorderLayout.CENTER)

        # -- Regex group (first capturing group) --
        self.regexEnable = JCheckBox("Extract from regex group", False)
        self.regexTf = JTextField(r'(?im)^Set-Cookie:\s*cognito-fl="([^"]+)"', 36)
        self.caseSens = JCheckBox("Case sensitive", False)

        pRegex = JPanel(GridBagLayout())
        gbc2 = GridBagConstraints()
        gbc2.insets = Insets(4, 6, 4, 6)
        gbc2.fill = GridBagConstraints.HORIZONTAL
        gbc2.anchor = GridBagConstraints.WEST

        gbc2.gridx = 0; gbc2.gridy = 0; gbc2.weightx = 1.0
        pRegex.add(self.regexTf, gbc2)
        gbc2.gridx = 0; gbc2.gridy = 1; gbc2.weightx = 0.0
        pRegex.add(self.caseSens, gbc2)

        regexOuter = JPanel(BorderLayout())
        regexOuter.add(self.regexEnable, BorderLayout.NORTH)
        regexOuter.add(pRegex, BorderLayout.CENTER)

        # -- Decoder / options / scope --
        self.decoder = JComboBox(DECODERS)
        self.maxOut = JTextField("300", 6)
        self.inHdrs = JCheckBox("Search headers", True)
        self.inBody = JCheckBox("Search body", False)
        self.replace = JCheckBox("Replace Comment (not append)", True)
        self.doHl = JCheckBox("Highlight row", True)
        self.enable = JCheckBox("Enable live decode (Intruder only)", True)

        pOpts = JPanel(GridBagLayout())
        gbc3 = GridBagConstraints()
        gbc3.insets = Insets(4, 6, 4, 6)
        gbc3.fill = GridBagConstraints.HORIZONTAL
        gbc3.anchor = GridBagConstraints.WEST

        def addOptRow(y, label, comp):
            gbc3.gridx = 0; gbc3.gridy = y; gbc3.weightx = 0.0
            pOpts.add(JLabel(label), gbc3)
            gbc3.gridx = 1; gbc3.weightx = 1.0
            pOpts.add(comp, gbc3)

        addOptRow(0, "Decoder:", self.decoder)
        addOptRow(1, "Comment max length:", self.maxOut)
        addOptRow(2, "Scope:", self._hbox(self.inHdrs, self.inBody))
        addOptRow(3, "Options:", self._hbox(self.replace, self.doHl))
        addOptRow(4, "", self.enable)

        grid = JPanel(GridBagLayout())
        gbcM = GridBagConstraints()
        gbcM.insets = Insets(6, 6, 6, 6)
        gbcM.fill = GridBagConstraints.BOTH
        gbcM.anchor = GridBagConstraints.NORTHWEST

        gbcM.gridx = 0; gbcM.gridy = 0; gbcM.weightx = 0.5; gbcM.weighty = 0.0
        grid.add(betweenOuter, gbcM)
        gbcM.gridx = 1; gbcM.gridy = 0; gbcM.weightx = 0.5; gbcM.weighty = 0.0
        grid.add(regexOuter, gbcM)
        gbcM.gridx = 0; gbcM.gridy = 1; gbcM.gridwidth = 2; gbcM.weightx = 1.0; gbcM.weighty = 0.0
        grid.add(pOpts, gbcM)

        outer = JPanel(BorderLayout())
        outer.add(grid, BorderLayout.NORTH)
        self.add(outer, BorderLayout.CENTER)

        # plumbing
        self._compiled = None
        self._cache = WeakHashMap()

        self._loadSettings()
        self._wirePersistence()
        self._normalizeExclusiveOnLoad()
        self._syncModeEnable()
        self._recompile()

    def _hbox(self, *comps):
        p = JPanel()
        for c in comps:
            p.add(c)
        return p

    def getTabCaption(self):
        return "BurpInlineDecoder"

    def getUiComponent(self):
        return self

    def _syncModeEnable(self):
        reOn = self.regexEnable.isSelected()
        beOn = self.betweenEnable.isSelected()
        for comp in (self.startAfterRb, self.startAfterTf, self.startAtOffRb, self.startAtOffTf,
                     self.endAtDelimRb, self.endAtDelimTf, self.endFixedRb, self.endFixedTf):
            comp.setEnabled(beOn)
        for comp in (self.regexTf, self.caseSens):
            comp.setEnabled(reOn)
        if not reOn and not beOn:
            self.betweenEnable.setSelected(True)
            self._syncModeEnable()

    def _normalizeExclusiveOnLoad(self):
        if self.regexEnable.isSelected() and self.betweenEnable.isSelected():
            self.betweenEnable.setSelected(False)

    # persistence
    def _saveSettings(self):
        setv = self.cb.saveExtensionSetting
        setv("betweenOn", "1" if self.betweenEnable.isSelected() else "0")
        setv("startAfter", self.startAfterTf.getText())
        setv("startUseOffset", "1" if self.startAtOffRb.isSelected() else "0")
        setv("startOffset", self.startAtOffTf.getText())
        setv("endDelim", self.endAtDelimTf.getText())
        setv("endUseFixed", "1" if self.endFixedRb.isSelected() else "0")
        setv("endFixed", self.endFixedTf.getText())
        setv("regexOn", "1" if self.regexEnable.isSelected() else "0")
        setv("regex", self.regexTf.getText())
        setv("case", "1" if self.caseSens.isSelected() else "0")
        setv("decoder", self.decoder.getSelectedItem())
        setv("inHdrs", "1" if self.inHdrs.isSelected() else "0")
        setv("inBody", "1" if self.inBody.isSelected() else "0")
        setv("maxOut", self.maxOut.getText())
        setv("replace", "1" if self.replace.isSelected() else "0")
        setv("doHl", "1" if self.doHl.isSelected() else "0")
        setv("enable", "1" if self.enable.isSelected() else "0")
        self._recompile()

    def _loadSettings(self):
        get = self.cb.loadExtensionSetting
        def g(k, d):
            v = get(k)
            return d if v is None else v
        self.betweenEnable.setSelected(g("betweenOn", "1") == "1")
        self.startAfterTf.setText(g("startAfter", "-Trial:"))
        if g("startUseOffset", "0") == "1":
            self.startAtOffRb.setSelected(True)
        else:
            self.startAfterRb.setSelected(True)
        self.startAtOffTf.setText(g("startOffset", "0"))
        self.endAtDelimTf.setText(g("endDelim", r"\r\nOrigin-"))
        if g("endUseFixed", "0") == "1":
            self.endFixedRb.setSelected(True)
        else:
            self.endAtDelimRb.setSelected(True)
        self.endFixedTf.setText(g("endFixed", "0"))
        self.regexEnable.setSelected(g("regexOn", "0") == "1")
        self.regexTf.setText(g("regex", r'(?im)^Set-Cookie:\s*cognito-fl="([^"]+)"'))
        self.caseSens.setSelected(g("case", "0") == "1")
        dec = g("decoder", "Auto (Base64)")
        try:
            self.decoder.setSelectedItem(dec)
        except:
            pass
        self.inHdrs.setSelected(g("inHdrs", "1") == "1")
        self.inBody.setSelected(g("inBody", "0") == "1")
        self.maxOut.setText(g("maxOut", "300"))
        self.replace.setSelected(g("replace", "1") == "1")
        self.doHl.setSelected(g("doHl", "1") == "1")
        self.enable.setSelected(g("enable", "1") == "1")

    def _wirePersistence(self):
        saver = _DocSave(self._saveSettings)
        for tf in (self.startAfterTf, self.startAtOffTf, self.endAtDelimTf,
                   self.endFixedTf, self.regexTf, self.maxOut):
            tf.getDocument().addDocumentListener(saver)
        for cb in (self.caseSens, self.inHdrs, self.inBody, self.replace, self.doHl,
                   self.enable, self.startAtOffRb, self.endFixedRb,
                   self.startAfterRb, self.endAtDelimRb,
                   self.regexEnable, self.betweenEnable):
            cb.addItemListener(_ItemSave(self._saveSettings))
        # mutual exclusion listeners
        self.regexEnable.addItemListener(_MutualToggle(self, "regex"))
        self.betweenEnable.addItemListener(_MutualToggle(self, "between"))

    def _recompile(self):
        flags = 0
        if not self.caseSens.isSelected():
            flags |= re.IGNORECASE
        try:
            self._compiled = re.compile(self.regexTf.getText(), flags | re.DOTALL | re.MULTILINE)
        except Exception:
            self._compiled = None

    # getters
    def isEnabled(self):  return self.enable.isSelected()
    def useRegex(self):   return self.regexEnable.isSelected()
    def useBetween(self): return self.betweenEnable.isSelected()

    def startUsesOffset(self): return self.startAtOffRb.isSelected()
    def getStartExpr(self):    return self.startAfterTf.getText()
    def getStartOffset(self):
        try:
            return max(0, int(self.startAtOffTf.getText().strip()))
        except:
            return 0

    def endUsesFixed(self):    return self.endFixedRb.isSelected()
    def getEndExpr(self):      return self.endAtDelimTf.getText()
    def getEndFixed(self):
        try:
            return max(0, int(self.endFixedTf.getText().strip()))
        except:
            return 0

    def getRegex(self):   return self.regexTf.getText()
    def isCase(self):     return self.caseSens.isSelected()
    def getDecoder(self): return self.decoder.getSelectedItem()
    def searchHdrs(self): return self.inHdrs.isSelected()
    def searchBody(self): return self.inBody.isSelected()
    def maxOutLen(self):
        try:
            return max(1, min(20000, int(self.maxOut.getText().strip())))
        except:
            return 300
    def replaceComment(self): return self.replace.isSelected()
    def doHighlight(self):    return self.doHl.isSelected()

# -------------------- Intruder listener --------------------

class LiveDecoder(IHttpListener):
    def __init__(self, callbacks, tab):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        self.tab = tab

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        if toolFlag != IBurpExtenderCallbacks.TOOL_INTRUDER:
            return
        if not self.tab.isEnabled():
            return

        resp = messageInfo.getResponse()
        if resp is None:
            return
        rinfo = self.helpers.analyzeResponse(resp)

        hay = []
        if self.tab.searchHdrs():
            hay.append(u"\r\n".join([to_text(h) for h in rinfo.getHeaders()]))
        if self.tab.searchBody():
            hay.append(to_text(resp[rinfo.getBodyOffset():]))
        if not hay:
            return

        extracted = None

        if self.tab.useRegex():
            pat = self.tab._compiled
            if pat is None:
                return
            for h in hay:
                m = pat.search(h)
                if m and m.groups():
                    extracted = m.group(1)
                    break

        elif self.tab.useBetween():
            start_expr = unescape_literals(self.tab.getStartExpr())
            end_expr   = unescape_literals(self.tab.getEndExpr())
            use_off    = self.tab.startUsesOffset()
            use_fixed  = self.tab.endUsesFixed()
            start_off  = self.tab.getStartOffset()
            end_len    = self.tab.getEndFixed()

            for h in hay:
                src = h
                if not self.tab.isCase():
                    src = h.lower()
                    start_expr_cmp = start_expr.lower()
                    end_expr_cmp   = end_expr.lower()
                else:
                    start_expr_cmp = start_expr
                    end_expr_cmp   = end_expr

                if use_off:
                    sidx = min(start_off, len(src))
                else:
                    sidx = src.find(start_expr_cmp) if start_expr_cmp else 0
                    if sidx == -1:
                        continue
                    sidx += len(start_expr_cmp)

                if use_fixed:
                    eidx = min(len(src), sidx + end_len)
                else:
                    if end_expr_cmp:
                        rel = src.find(end_expr_cmp, sidx)
                        if rel == -1:
                            continue
                        eidx = rel
                    else:
                        eidx = len(src)

                extracted = h[sidx:eidx]
                break

        if not extracted:
            return

        dec_name = self.tab.getDecoder()
        try:
            cleaned = sanitize_for_decoder(extracted, dec_name)
            decoded = to_text(DEC_FN[dec_name](cleaned))
            out = decoded[: self.tab.maxOutLen()]
        except Exception as e:
            out = u"<decode error: %s>" % to_text(str(e))

        last = self.tab._cache.get(messageInfo)
        if last == out:
            return
        self.tab._cache.put(messageInfo, out)

        cur = messageInfo.getComment() or u""
        if self.tab.replaceComment() or not cur:
            newc = out
        else:
            newc = cur + (u" | " if cur else u"") + out
        messageInfo.setComment(newc)
        if self.tab.doHighlight():
            messageInfo.setHighlight("cyan")

# -------------------- Burp entry --------------------

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("BurpInlineDecoder v%s" % __version__)
        tab = GrepXTab(callbacks)
        callbacks.addSuiteTab(tab)
        callbacks.registerHttpListener(LiveDecoder(callbacks, tab))
