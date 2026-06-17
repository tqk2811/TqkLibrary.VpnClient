using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenConnect.Tests
{
    /// <summary>
    /// Tests the OpenConnect/ocserv HTTPS auth codec (V5.a): building the init/reply config-auth bodies, parsing a
    /// served form into fields, detecting the success terminal, and extracting the session cookie.
    /// </summary>
    public class OpenConnectAuthCodecTests
    {
        [Fact]
        public void BuildInitRequest_IsWellFormedConfigAuth()
        {
            string body = OpenConnectAuthCodec.BuildInitRequest();
            Assert.Contains("<config-auth", body);
            Assert.Contains("type=\"init\"", body);
            Assert.Contains(OpenConnectAuthCodec.AnyConnectVersion, body);
            // Round-trips through the form parser as "no form yet" (init has no <form>), not a crash.
            Assert.DoesNotContain("\n", body); // single-line (DisableFormatting)
        }

        [Fact]
        public void TryParseForm_ServedForm_ExtractsUsernamePasswordFields()
        {
            const string xml =
                "<auth id=\"main\">" +
                  "<message>Please enter your username and password.</message>" +
                  "<form method=\"post\" action=\"/auth\">" +
                    "<input type=\"text\" name=\"username\" label=\"Username:\" />" +
                    "<input type=\"password\" name=\"password\" label=\"Password:\" />" +
                  "</form>" +
                "</auth>";

            Assert.True(OpenConnectAuthCodec.TryParseForm(xml, out OpenConnectAuthForm form));
            Assert.Equal("main", form.AuthId);
            Assert.Equal("Please enter your username and password.", form.Message);
            Assert.Equal(2, form.Fields.Count);
            Assert.Equal("username", form.Fields[0].Name);
            Assert.Equal("text", form.Fields[0].Type);
            Assert.Equal("Username:", form.Fields[0].Label);
            Assert.Equal("password", form.Fields[1].Name);
            Assert.Equal("password", form.Fields[1].Type);
        }

        [Fact]
        public void BuildReplyRequest_CarriesAuthIdAndFilledValues()
        {
            const string xml =
                "<auth id=\"main\"><form><input type=\"text\" name=\"username\"/>" +
                "<input type=\"password\" name=\"password\"/></form></auth>";
            Assert.True(OpenConnectAuthCodec.TryParseForm(xml, out OpenConnectAuthForm form));
            form.SetValue("username", "alice");
            form.SetValue("password", "s3cr3t");

            string reply = OpenConnectAuthCodec.BuildReplyRequest(form);

            Assert.Contains("type=\"auth-reply\"", reply);
            Assert.Contains("id=\"main\"", reply);
            Assert.Contains("<username>alice</username>", reply);
            Assert.Contains("<password>s3cr3t</password>", reply);
        }

        [Fact]
        public void TryParseForm_Success_ReturnsFalse_AndIsSuccessTrue()
        {
            const string xml = "<auth id=\"success\"><message>Success</message></auth>";
            Assert.False(OpenConnectAuthCodec.TryParseForm(xml, out _));
            Assert.True(OpenConnectAuthCodec.IsSuccess(xml));
        }

        [Fact]
        public void TryParseForm_FormWithNoInputs_ReturnsFalse()
        {
            const string xml = "<auth id=\"main\"><message>Just a notice</message></auth>";
            Assert.False(OpenConnectAuthCodec.TryParseForm(xml, out OpenConnectAuthForm form));
            Assert.False(OpenConnectAuthCodec.IsSuccess(xml));
            Assert.Equal("Just a notice", form.Message);
        }

        [Fact]
        public void TryParseForm_RejectsNonXml()
        {
            Assert.Throws<FormatException>(() => OpenConnectAuthCodec.TryParseForm("not xml at all <", out _));
        }

        [Fact]
        public void TryParseForm_RejectsUnexpectedRoot()
        {
            Assert.Throws<FormatException>(() => OpenConnectAuthCodec.TryParseForm("<html><body/></html>", out _));
        }

        [Theory]
        [InlineData("Set-Cookie: webvpn=ABC123XYZ; Secure; HttpOnly", "webvpn=ABC123XYZ")]
        [InlineData("webvpn=PLAIN; path=/", "webvpn=PLAIN")]
        public void ExtractCookie_PullsWebvpnPair(string header, string expected)
        {
            Assert.Equal(expected, OpenConnectAuthCodec.ExtractCookie(header));
        }

        [Fact]
        public void ExtractCookie_IgnoresOtherCookies()
        {
            Assert.Null(OpenConnectAuthCodec.ExtractCookie("Set-Cookie: webvpncontext=foo; Secure", "webvpn"));
        }

        [Fact]
        public void SetValue_OnUnknownField_AddsIt()
        {
            var form = new OpenConnectAuthForm();
            form.SetValue("group_list", "Employees");
            Assert.Single(form.Fields);
            Assert.Equal("group_list", form.Fields[0].Name);
            Assert.Equal("Employees", form.Fields[0].Value);
        }
    }
}
