# Cloudflare contract fixtures

`documented-examples.json` holds payloads adapted from the examples in
Cloudflare's public API documentation
(<https://developers.cloudflare.com/api/resources/zones/> and
<https://developers.cloudflare.com/api/resources/dns/subresources/records/>).
They use the documentation's example ids, `example.com`, and RFC 5737 and
RFC 3849 addresses. They were **not** captured from a live account: no live
token was available when FM-1042 was written, and the error codes in the
error entries are the ones the documentation lists, not observed ones.

To record scrubbed fixtures from a real account, run the ignored capture test
(`tests/capture.rs`) with a token that has `Zone:Read` and `DNS:Read` only.
Review the output before committing it: the repository is public.
