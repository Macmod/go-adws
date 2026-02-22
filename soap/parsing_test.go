package soap

import (
	"strings"
	"testing"
)

func TestParseEnumerateResponse_Success(t *testing.T) {
	xml := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><wsen:EnumerateResponse xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><wsen:EnumerationContext>ctx-123</wsen:EnumerationContext></wsen:EnumerateResponse></s:Body></s:Envelope>`

	resp, err := ParseEnumerateResponse(xml)
	if err != nil {
		t.Fatalf("ParseEnumerateResponse returned error: %v", err)
	}
	if resp.EnumerationContext != "ctx-123" {
		t.Fatalf("unexpected context: %q", resp.EnumerationContext)
	}
	if resp.EndOfSequence {
		t.Fatalf("expected EndOfSequence=false")
	}
}

func TestParseEnumerateResponse_Fault(t *testing.T) {
	xml := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text>bad request</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>`

	_, err := ParseEnumerateResponse(xml)
	if err == nil {
		t.Fatal("expected fault error")
	}
	if !strings.Contains(err.Error(), "SOAP Fault") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePullResponse_DynamicObjects(t *testing.T) {
	xml := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><wsen:PullResponse xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><wsen:EnumerationContext>ctx-next</wsen:EnumerationContext><wsen:Items><addata:user><ad:objectReferenceProperty><ad:value xsi:type="xsd:string">guid-ref-1</ad:value></ad:objectReferenceProperty><addata:distinguishedName LdapSyntax="DNString"><ad:value xsi:type="xsd:string">CN=John,DC=example,DC=com</ad:value></addata:distinguishedName><addata:objectGUID LdapSyntax="OctetString"><ad:value xsi:type="xsd:base64Binary">TysO7MnM6kWim11raT2qnQ==</ad:value></addata:objectGUID><addata:cn LdapSyntax="UnicodeString"><ad:value xsi:type="xsd:string">John</ad:value></addata:cn></addata:user><addata:group><ad:objectReferenceProperty><ad:value xsi:type="xsd:string">guid-ref-2</ad:value></ad:objectReferenceProperty><addata:cn LdapSyntax="UnicodeString"><ad:value xsi:type="xsd:string">Domain Users</ad:value></addata:cn></addata:group></wsen:Items><wsen:EndOfSequence></wsen:EndOfSequence></wsen:PullResponse></s:Body></s:Envelope>`

	resp, err := ParsePullResponse(xml)
	if err != nil {
		t.Fatalf("ParsePullResponse returned error: %v", err)
	}

	if resp.EnumerationContext != "ctx-next" {
		t.Fatalf("unexpected context: %q", resp.EnumerationContext)
	}
	if !resp.EndOfSequence {
		t.Fatalf("expected EndOfSequence=true")
	}
	if len(resp.Items) != 2 {
		t.Fatalf("unexpected item count: %d", len(resp.Items))
	}

	if resp.Items[0].DistinguishedName != "CN=John,DC=example,DC=com" {
		t.Fatalf("unexpected DN: %q", resp.Items[0].DistinguishedName)
	}
	if resp.Items[0].ObjectGUID != "ec0e2b4f-ccc9-45ea-a29b-5d6b693daa9d" {
		t.Fatalf("unexpected objectGUID decode: %q", resp.Items[0].ObjectGUID)
	}
	if got := resp.Items[0].Attributes["cn"][0].Value; got != "John" {
		t.Fatalf("unexpected cn value: %q", got)
	}

	if resp.Items[1].ObjectGUID != "guid-ref-2" {
		t.Fatalf("expected object reference fallback for objectGUID, got %q", resp.Items[1].ObjectGUID)
	}
}

func TestParsePullResponse_Fault(t *testing.T) {
	xml := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>server error</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>`

	_, err := ParsePullResponse(xml)
	if err == nil {
		t.Fatal("expected fault error")
	}
	if !strings.Contains(err.Error(), "SOAP Fault") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseBaseObjectSearchResponse_Success(t *testing.T) {
	xml := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</a:Action></s:Header><s:Body><da:BaseObjectSearchResponse xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"><da:PartialAttribute><addata:distinguishedName LdapSyntax="DSDNString"><ad:value xsi:type="xsd:string">CN=John,DC=example,DC=com</ad:value></addata:distinguishedName></da:PartialAttribute><da:PartialAttribute><addata:cn LdapSyntax="UnicodeString"><ad:value xsi:type="xsd:string">John</ad:value></addata:cn></da:PartialAttribute></da:BaseObjectSearchResponse></s:Body></s:Envelope>`

	item, err := ParseBaseObjectSearchResponse(xml)
	if err != nil {
		t.Fatalf("ParseBaseObjectSearchResponse returned error: %v", err)
	}
	if item.DistinguishedName != "CN=John,DC=example,DC=com" {
		t.Fatalf("unexpected DN: %q", item.DistinguishedName)
	}
	if got := item.Attributes["cn"][0].Value; got != "John" {
		t.Fatalf("unexpected cn: %q", got)
	}
}

func TestParseWSTransferCreateAddress_FromResourceCreatedAddress(t *testing.T) {
	xml := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:wsa="http://www.w3.org/2005/08/addressing"><s:Body><wst:CreateResponse><wst:ResourceCreated><wsa:Address>net.tcp://dc.example.com:9389/ActiveDirectoryWebServices/Windows/Resource?obj=abc</wsa:Address></wst:ResourceCreated></wst:CreateResponse></s:Body></s:Envelope>`

	got, err := ParseWSTransferCreateAddress(xml)
	if err != nil {
		t.Fatalf("ParseWSTransferCreateAddress returned error: %v", err)
	}
	if !strings.Contains(got, "net.tcp://dc.example.com") {
		t.Fatalf("unexpected address: %q", got)
	}
}

func TestParseWSTransferCreateAddress_FromObjectReferencePropertyValue(t *testing.T) {
	xml := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><s:Body><wst:CreateResponse><ad:objectReferenceProperty><ad:value xsi:type="xsd:string">guid-ref-123</ad:value></ad:objectReferenceProperty></wst:CreateResponse></s:Body></s:Envelope>`

	got, err := ParseWSTransferCreateAddress(xml)
	if err != nil {
		t.Fatalf("ParseWSTransferCreateAddress returned error: %v", err)
	}
	if got != "guid-ref-123" {
		t.Fatalf("unexpected object reference: %q", got)
	}
}

func TestScopeToString(t *testing.T) {
	tests := []struct {
		scope int
		want  string
	}{
		{0, "Base"},
		{1, "OneLevel"},
		{2, "Subtree"},
		{999, "Subtree"},
	}

	for _, tc := range tests {
		if got := ScopeToString(tc.scope); got != tc.want {
			t.Fatalf("scopeToString(%d)=%q want %q", tc.scope, got, tc.want)
		}
	}
}
