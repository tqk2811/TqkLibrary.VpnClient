using System.Collections.Generic;

namespace TqkLibrary.VpnClient.OpenConnect.Models
{
    /// <summary>
    /// An ocserv/AnyConnect authentication form: the set of input fields the gateway asks the client to fill (from the
    /// XML <c>&lt;auth&gt;</c> body it serves on the first POST) plus the values the client submits back. The client
    /// posts these as a small XML config-auth document; the gateway answers with either another form (multi-step /
    /// group select) or a success carrying the session cookie.
    /// </summary>
    public sealed class OpenConnectAuthForm
    {
        /// <summary>The opaque auth-state token the gateway threads through a multi-step exchange (<c>&lt;auth id="…"&gt;</c>).</summary>
        public string? AuthId { get; set; }

        /// <summary>A human-readable message/title the gateway attached to the form, if any.</summary>
        public string? Message { get; set; }

        /// <summary>The form fields, in order — typically <c>username</c> then <c>password</c> (and <c>group_list</c>).</summary>
        public List<OpenConnectAuthField> Fields { get; } = new();

        /// <summary>Convenience: sets (or adds) a text value for the field named <paramref name="name"/>.</summary>
        public void SetValue(string name, string value)
        {
            foreach (OpenConnectAuthField f in Fields)
            {
                if (string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase)) { f.Value = value; return; }
            }
            Fields.Add(new OpenConnectAuthField(name, "text") { Value = value });
        }
    }

    /// <summary>One field of an <see cref="OpenConnectAuthForm"/> — its wire <see cref="Name"/>, input <see cref="Type"/>
    /// (<c>text</c>/<c>password</c>/<c>select</c>), an optional human <see cref="Label"/>, and the submitted <see cref="Value"/>.</summary>
    public sealed class OpenConnectAuthField
    {
        /// <summary>Creates a field with a wire name and input type.</summary>
        public OpenConnectAuthField(string name, string type)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Type = type ?? throw new ArgumentNullException(nameof(type));
        }

        /// <summary>The form-field name posted back to the gateway.</summary>
        public string Name { get; }

        /// <summary>The input type (<c>text</c>, <c>password</c>, <c>select</c>).</summary>
        public string Type { get; }

        /// <summary>A human-readable label the gateway supplied for the field, if any.</summary>
        public string? Label { get; set; }

        /// <summary>The value the client submits for this field.</summary>
        public string? Value { get; set; }
    }
}
