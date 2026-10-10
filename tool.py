#!/usr/bin/env python3
"""Strictly decode and re-encode with a user-selected standard-library text codec."""
from _support import InputError, Parser, Report, cli, guarded, limits, positive, read_file
TOOL='encoding-roundtrip-audit'
ENCODINGS={'utf-8','utf-8-sig','utf-16','utf-16-le','utf-16-be','utf-32','utf-32-le','utf-32-be','ascii','latin-1','cp1252','shift-jis','cp932','euc-jp','iso2022-jp','gb18030','gbk','big5','koi8-r'}
ALIASES={'utf8':'utf-8','utf16':'utf-16','utf32':'utf-32','latin1':'latin-1','iso-8859-1':'latin-1','us-ascii':'ascii','windows-1252':'cp1252'}

@guarded(TOOL)
def audit(path, *, encoding, max_bytes=16777216,max_findings=1000):
    limits(max_bytes=max_bytes,max_findings=max_findings)
    if not isinstance(encoding,str):raise InputError('an explicit supported encoding is required')
    encoding=encoding.lower().replace('_','-');encoding=ALIASES.get(encoding,encoding)
    if encoding not in ENCODINGS:raise InputError('unsupported encoding; see --help for the explicit allowlist')
    data=read_file(path,max_bytes);report=Report(TOOL,max_findings)
    summary={'bytes':len(data),'encoding':encoding}
    try:text=data.decode(encoding,'strict')
    except UnicodeDecodeError as exc:
        report.add('decode_error',byte_offset=exc.start);return report.finish(summary)
    except UnicodeError:
        report.add('decode_error');return report.finish(summary)
    summary['characters']=len(text)
    try:encoded=text.encode(encoding,'strict')
    except UnicodeEncodeError as exc:
        report.add('encode_error',character_offset=exc.start);return report.finish(summary)
    summary['roundtrip_bytes']=len(encoded)
    if data!=encoded:
        report.add('non_roundtrip_encoding',original_bytes=len(data),roundtrip_bytes=len(encoded))
    return report.finish(summary)

def parse_and_audit():
    p=Parser(description=__doc__);p.add_argument('file');p.add_argument('--encoding',required=True,help='Explicit codec: '+', '.join(sorted(ENCODINGS)))
    p.add_argument('--max-bytes',type=positive,default=16777216);p.add_argument('--max-findings',type=positive,default=1000)
    a=vars(p.parse_args());path=a.pop('file');return audit(path,**a)
if __name__=='__main__':raise SystemExit(cli(TOOL,parse_and_audit))
