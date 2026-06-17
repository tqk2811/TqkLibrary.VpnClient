using System.Text;
using System.Xml.Linq;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// Pure codec for the ocserv/AnyConnect HTTPS authentication exchange that precedes the CSTP tunnel. The client
    /// POSTs an XML <c>&lt;config-auth&gt;</c> document to <c>/</c>; the gateway answers with either another
    /// <c>&lt;auth&gt;</c> form (more steps) or an <c>&lt;auth id="success"&gt;</c> carrying the session cookie that the
    /// HTTP CONNECT then presents. This type only builds request bodies and parses response bodies — no I/O. Modelled
    /// from the documented behaviour (draft-mavrogiannopoulos-openconnect / ocserv), not copied from GPL source.
    /// </summary>
    public static class OpenConnectAuthCodec
    {
        /// <summary>The protocol token the client advertises in the initial config-auth request.</summary>
        public const string AnyConnectVersion = "4.7.00136";

        /// <summary>
        /// Builds the initial <c>&lt;config-auth type="init"&gt;</c> XML body the client POSTs to begin authentication.
        /// </summary>
        public static string BuildInitRequest(string groupSelect = "")
        {
            var auth = new XElement("auth", new XElement("version", new XAttribute("who", "vpn"), AnyConnectVersion));
            if (!string.IsNullOrEmpty(groupSelect))
                auth.Add(new XElement("group-select", groupSelect));
            var doc = new XElement("config-auth",
                new XAttribute("client", "vpn"),
                new XAttribute("type", "init"),
                auth);
            return Serialize(doc);
        }

        /// <summary>
        /// Builds the <c>&lt;config-auth type="auth-reply"&gt;</c> XML body that submits a completed
        /// <paramref name="form"/> back to the gateway (carrying the auth-state token and every field value).
        /// </summary>
        public static string BuildReplyRequest(OpenConnectAuthForm form)
        {
            if (form is null) throw new ArgumentNullException(nameof(form));
            var auth = new XElement("auth");
            if (!string.IsNullOrEmpty(form.AuthId))
                auth.Add(new XAttribute("id", form.AuthId!));
            foreach (OpenConnectAuthField field in form.Fields)
                auth.Add(new XElement(field.Name, field.Value ?? string.Empty));
            var doc = new XElement("config-auth",
                new XAttribute("client", "vpn"),
                new XAttribute("type", "auth-reply"),
                auth);
            return Serialize(doc);
        }

        /// <summary>
        /// Parses a gateway auth response body. Returns true and fills <paramref name="form"/> when the gateway served
        /// a form (more input required); the <c>id</c> attribute is carried in <see cref="OpenConnectAuthForm.AuthId"/>.
        /// Returns false when the body is a terminal result — inspect <see cref="IsSuccess"/> on the same body for that.
        /// Throws <see cref="FormatException"/> when the body is not a recognised <c>&lt;auth&gt;</c>/<c>&lt;config-auth&gt;</c> document.
        /// </summary>
        public static bool TryParseForm(string responseBody, out OpenConnectAuthForm form)
        {
            form = new OpenConnectAuthForm();
            XElement auth = ParseAuthElement(responseBody);

            string? id = (string?)auth.Attribute("id");
            // A success/failure terminal result is not a form to fill.
            if (string.Equals(id, "success", StringComparison.OrdinalIgnoreCase)) return false;

            form.AuthId = id;
            form.Message = (string?)auth.Element("message");

            XElement? formEl = auth.Element("form");
            if (formEl == null) return false; // no <form> ⇒ nothing to fill (e.g. a bare error/message)

            foreach (XElement inputEl in formEl.Elements())
            {
                if (!string.Equals(inputEl.Name.LocalName, "input", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(inputEl.Name.LocalName, "select", StringComparison.OrdinalIgnoreCase))
                    continue;
                string? name = (string?)inputEl.Attribute("name");
                if (string.IsNullOrEmpty(name)) continue;
                string type = (string?)inputEl.Attribute("type")
                    ?? (string.Equals(inputEl.Name.LocalName, "select", StringComparison.OrdinalIgnoreCase) ? "select" : "text");
                form.Fields.Add(new OpenConnectAuthField(name!, type) { Label = (string?)inputEl.Attribute("label") });
            }
            return form.Fields.Count > 0;
        }

        /// <summary>True if the auth response body is the terminal <c>&lt;auth id="success"&gt;</c> result.</summary>
        public static bool IsSuccess(string responseBody)
        {
            XElement auth = ParseAuthElement(responseBody);
            return string.Equals((string?)auth.Attribute("id"), "success", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts the session cookie value from an HTTP <c>Set-Cookie</c> header line (e.g.
        /// <c>Set-Cookie: webvpn=ABC123; Secure; HttpOnly</c> ⇒ <c>webvpn=ABC123</c>). Returns null when the line is not
        /// a Set-Cookie for the requested <paramref name="cookieName"/>.
        /// </summary>
        public static string? ExtractCookie(string setCookieHeader, string cookieName = "webvpn")
        {
            if (string.IsNullOrEmpty(setCookieHeader)) return null;
            int colon = setCookieHeader.IndexOf(':');
            string value = colon >= 0 ? setCookieHeader.Substring(colon + 1).Trim() : setCookieHeader.Trim();
            // The cookie is the first attribute, up to the first ';'.
            int semicolon = value.IndexOf(';');
            string pair = (semicolon >= 0 ? value.Substring(0, semicolon) : value).Trim();
            int eq = pair.IndexOf('=');
            if (eq <= 0) return null;
            string name = pair.Substring(0, eq).Trim();
            return string.Equals(name, cookieName, StringComparison.OrdinalIgnoreCase) ? pair : null;
        }

        static XElement ParseAuthElement(string responseBody)
        {
            if (string.IsNullOrWhiteSpace(responseBody))
                throw new FormatException("Empty OpenConnect auth response body.");
            XElement root;
            try { root = XElement.Parse(responseBody); }
            catch (System.Xml.XmlException ex) { throw new FormatException("OpenConnect auth response is not well-formed XML.", ex); }

            if (string.Equals(root.Name.LocalName, "auth", StringComparison.OrdinalIgnoreCase)) return root;
            if (string.Equals(root.Name.LocalName, "config-auth", StringComparison.OrdinalIgnoreCase))
            {
                XElement? auth = root.Element("auth");
                if (auth != null) return auth;
            }
            throw new FormatException($"Unexpected OpenConnect auth root element '<{root.Name.LocalName}>'.");
        }

        static string Serialize(XElement doc)
        {
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sb.Append(doc.ToString(SaveOptions.DisableFormatting));
            return sb.ToString();
        }
    }
}
