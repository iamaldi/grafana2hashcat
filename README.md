<h1 align="center">Grafana2Hashcat</h1>
<h5 align="center">Grafana2Hashcat makes it easy to convert Grafana hashes to PBKDF_HMAC_SHA256 format in order to facilitate password cracking using Hashcat.</h5>

## Introduction

Grafana is a multi-platform open source analytics and interactive visualization web application. It provides charts, graphs, and alerts for the web when connected to supported data sources.

During security assessments you might come across a Grafana database, and get ahold of the users password hash digests. By default, the Grafana hash digests are not in a format supported by popular password cracking tools, such as Hashcat. Grafana uses the PBKDF2_HMAC_SHA256 hashing algorithm, and stores the hash digests in hexadecimal, and the salt value in plaintext format in the database.

This can be confirmed by taking a look directly at the responsible code:
```go
// File: https://github.com/grafana/grafana/blob/f496c31018cdb5ecc8b3c30ea96a235a5bcf470a/pkg/util/encoding.go#L33-L37
// Commit: https://github.com/grafana/grafana/commit/574553ec7bb5e61c6a362ceb9f28cc9e1c8f6f63
[...]

// EncodePassword encodes a password using PBKDF2.
func EncodePassword(password string, salt string) (string, error) {
	newPasswd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(newPasswd), nil
}

[...]
```

For example, the password `secret` with a [non-random] salt value of `pepper` is [transformed](https://play.golang.org/p/t2rzj87i_en) to the following entry in the Grafana database (bear in mind these are two separate columns in the DB):

```hex
3ad31dc57a7452c442f259cfff7aa61f2a6cea88ee634724ae146e221ae4e01c56c8bcbb3552310acd2fd746a396d2f99bf8,pepper
```

Tools such as Hashcat, however, require the PBKDF2_HMAC_SHA256 hash digest in the following format:

```
sha256:NumberOfIterations:Base64EncodedSalt:Base64EncodedDigest
```

For example, the previously mentioned Grafana hash digest can be transformed in following Hashcat equivalent:
```
sha256:10000:cGVwcGVy:OtMdxXp0UsRC8lnP/3qmHyps6ojuY0ckrhRuIhrk4BxWyLy7NVIxCs0v10ajltL5m/g=
```

This entry can then be imported in Hashcat in order to start the password cracking process.


## Usage
```console
usage: grafana2hashcat.py [-h] [-o outfile] hashes

Convert Grafana hashes to Hashcat's PBKDF2_HMAC_SHA256 format.

positional arguments:
  hashes      Input file holding the Grafana hashes in the 'hash,salt' format.

optional arguments:
  -h, --help  show this help message and exit
  -o outfile  Output filename to save the Hashcat's PBKDF2_HMAC_SHA256 hashes.
              Default is stdout.
```

### Example usage

```console
user@host:~$ cat grafana_hashes.txt
3ad31dc57a7452c442f259cfff7aa61f2a6cea88ee634724ae146e221ae4e01c56c8bcbb3552310acd2fd746a396d2f99bf8,pepper
6ceeee16107218b057249050a03aab9d72baa6f31345b5ed20a1f56f20a35cfdc0f50e5b15c310151e851094f4e0a779bb28,pepper
8daf61545e7f9c9b1fe35e668425c15cdd4f101187c30ce7257e33cd0e94216abb05d5e2f73d28d4c98fcd9227536676c3e7,pepper
```

```console
user@host:~$ python3 grafana2hashcat.py grafana_hashes.txt

[+] Grafana2Hashcat
[+] Reading Grafana hashes from:  ./grafana_hashes.txt
[+] Done! Read 3 hashes in total.
[+] Converting hashes...
[+] Converting hashes complete.
[*] Outfile was not declared, printing output to stdout instead.

sha256:10000:cGVwcGVy:OtMdxXp0UsRC8lnP/3qmHyps6ojuY0ckrhRuIhrk4BxWyLy7NVIxCs0v10ajltL5m/g=
sha256:10000:cGVwcGVy:bO7uFhByGLBXJJBQoDqrnXK6pvMTRbXtIKH1byCjXP3A9Q5bFcMQFR6FEJT04Kd5uyg=
sha256:10000:cGVwcGVy:ja9hVF5/nJsf415mhCXBXN1PEBGHwwznJX4zzQ6UIWq7BdXi9z0o1MmPzZInU2Z2w+c=


[+] Now, you can run Hashcat with the following command, for example:

hashcat -m 10900 hashcat_hashes.txt --wordlist wordlist.txt
```
