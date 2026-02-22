<p align="center">
  <h1 align="center"><b>go-adws</b></h1>
  <p align="center"><i>A Go implementation of the Active Directory Web Services (ADWS) protocol stack.</i></p>
  <p align="center">
    <img src="https://img.shields.io/github/v/release/Macmod/go-adws" alt="GitHub Release">
    <img src="https://img.shields.io/github/go-mod/go-version/Macmod/go-adws" alt="Go Version">
    <img src="https://img.shields.io/github/languages/code-size/Macmod/go-adws" alt="Code Size">
    <img src="https://img.shields.io/github/license/Macmod/go-adws" alt="License">
    <a href="https://goreportcard.com/report/github.com/Macmod/go-adws"><img src="https://goreportcard.com/badge/github.com/Macmod/go-adws" alt="Go Report Card"></a>
    <img src="https://img.shields.io/github/downloads/Macmod/go-adws/total" alt="GitHub Downloads">
    <a href="https://twitter.com/MacmodSec"><img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/MacmodSec?style=for-the-badge&logo=X&color=blue"></a>
  </p>
</p>


```
    Client
      |
  +-----------+   package wscap          MS-ADCAP  (Custom Actions)
  | wscap     |   package wstransfer     MS-WSTIM  (WS-Transfer + IMDA extensions)
  | wstransfer|   package wsenum         MS-WSDS   (WS-Enumeration extensions)
  | wsenum    |
  +-----------+
      |  SOAP 1.2 XML (UTF-8) built by package soap
      |
  +-----------+   package transport/nmf  MC-NMF    (.NET Message Framing)
  |   NMF     |   SizedEnvelope records; binary dict encoding (MC-NBFSE)
  +-----------+
      |
  +-----------+   package transport/nns  MS-NNS    (.NET NegotiateStream)
  |   NNS     |   SPNEGO handshake; GSS_Wrap/Unwrap per message
  +-----------+
      |
  DomainController:9389
```

# Contributing

Contributions are welcome by [opening an issue](https://github.com/Macmod/go-adws/issues/new) or by [submitting a pull request](https://github.com/Macmod/go-adws/pulls).

# Acknowledgements

* Big thanks to [oiweiwei](https://github.com/oiweiwei) for [go-msrpc](https://github.com/oiweiwei/go-msrpc), as his `ssp` package implemented the authentication flow with GSSAPI seamlessly.

# References

- [MS-NNS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns) - .NET NegotiateStream Protocol
- [MS-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf) - .NET Message Framing Protocol
- [MS-ADDM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-addm) - Active Directory Web Services: Data Model and Common Elements
- [MS-WSDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsds) - WS-Enumeration: Directory Services Protocol Extensions
- [MS-WSTIM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-wstim) - WS-Transfer: Identity Management Operations for Directory Access Extensions
- [MS-ADCAP](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-adcap) - Active Directory Web Services Custom Action Protocol
- [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts) - Active Directory Technical Specification

# License

The MIT License (MIT)

Copyright (c) 2023 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
