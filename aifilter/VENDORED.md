# Public Suffix List

`public_suffix_list.dat` is a complete offline PSL snapshot, including its ICANN
and PRIVATE sections, under Mozilla Public License 2.0 (license notice retained
in the file). Upstream: <https://publicsuffix.org/list/public_suffix_list.dat>.
Matching rules: <https://github.com/publicsuffix/list/wiki/Format>.

This copy was extracted on 2026-11-10 from the installed Tcl 9 cookiejar 0.2
runtime's bundled `public_suffix_list.dat.gz`, because this development sandbox
cannot resolve public network hosts. The upstream revision/date of that bundled
snapshot is unknown; this is not a claim that the list is current.

SHA-256 of the uncompressed vendored file:
`6d5a41890175e65826f2a3532369925067d840e324631eb8b8008dc5f9ffebad`.

To refresh, download the official source above in an authorized network-enabled
environment, retain its license notice and both sections, update the checksum
and provenance here, and run the PSL regression tests. There is no runtime
network refresh or package download.
