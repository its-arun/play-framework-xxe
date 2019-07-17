# play-framework-xxe
POC for exploitation of a XML entities in the Play framework useful for CTFs where you might not have access to VPS. This POC assumes that the host provided by user is vulnerable to said play framework xxe. [Read More](https://www.playframework.com/security/vulnerability/20130920-XmlExternalEntity)

## Usage
```
git clone https://github.com/its-arun/play-framework-xxe.git
cd play-framework-xxe
python3 poc.py http://example.com/login
```

## Spin yourself a vulnerable instance
Pentesterlab was kind enough to publish exercise for this vulnerability at [VulnHub](https://www.vulnhub.com/entry/pentester-lab-play-xml-entities,119/)
