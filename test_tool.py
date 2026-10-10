import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location("audit_tool",Path(__file__).with_name("tool.py"))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def codes(self,result):return {x["code"] for x in result.get("findings",[])}
    def call(self,*args):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name("tool.py")),*map(str,args)],capture_output=True,text=True)
        return result.returncode,json.loads(result.stdout)
    def test_bad_cli(self):
        code,result=self.call("--unknown");self.assertEqual(code,2);self.assertEqual(result["status"],"error")
    def test_examples(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/"examples"/"run_examples.py")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reports=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([r["status"] for r in reports],["pass","findings"])

    def write(self,data):
        p=self.root/'input.txt';p.write_bytes(data);return p
    def test_unicode_and_cli(self):
        p=self.write('café'.encode());self.assertEqual(tool.audit(p,encoding='utf8')['status'],'pass');self.assertEqual(self.call(p,'--encoding','utf-8')[0],0)
    def test_decode_failure(self):
        p=self.write(b'\xff');r=tool.audit(p,encoding='ascii');self.assertIn('decode_error',self.codes(r));self.assertEqual(self.call(p,'--encoding','ascii')[0],1);self.assertNotIn('\\xff',json.dumps(r))
    def test_roundtrip_failure_without_bom(self):
        p=self.write(b'hello');self.assertIn('non_roundtrip_encoding',self.codes(tool.audit(p,encoding='utf-8-sig')))
        p.write_bytes(b'\xef\xbb\xbfhello');self.assertEqual(tool.audit(p,encoding='utf-8-sig')['status'],'pass')
    def test_utf16_explicit(self):
        p=self.write('hello'.encode('utf-16'));self.assertEqual(tool.audit(p,encoding='utf-16')['status'],'pass')
        p.write_bytes(b'h\x00i');self.assertIn('decode_error',self.codes(tool.audit(p,encoding='utf-16-le')))
    def test_single_byte_is_not_detection(self):
        p=self.write(b'\xff');self.assertEqual(tool.audit(p,encoding='latin-1')['status'],'pass');self.assertIn('decode_error',self.codes(tool.audit(p,encoding='utf-8')))
    def test_allowlist_limits_and_permissions(self):
        p=self.write(b'hello');self.assertEqual(tool.audit(p,encoding='base64_codec')['status'],'error');self.assertEqual(tool.audit(p,encoding='utf-8',max_bytes=1)['status'],'error');self.assertEqual(self.call(p)[0],2)
        with mock.patch.object(tool,'read_file',side_effect=PermissionError):self.assertEqual(tool.audit(p,encoding='ascii')['status'],'error')
    def test_symlink(self):
        p=self.write(b'a');q=self.root/'link';q.symlink_to(p);self.assertEqual(tool.audit(q,encoding='ascii')['status'],'error')

    def test_support_rejects_symlink_before_dotdot(self):
        import _support
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to('actual');(self.root/'safe').write_bytes(b'x')
        with self.assertRaises((OSError,_support.InputError)):
            with _support.anchored(str(self.root)+'/alias/../safe'):
                self.fail('must not normalize away a symlink component')
    def test_support_detects_pre_read_mutation(self):
        import _support
        p=self.root/'changed';p.write_bytes(b'a');before=p.stat();p.write_bytes(b'longer')
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):_support.read_at(fd,'changed',before,100)
    def test_support_entry_budget_and_host_guard(self):
        import _support
        (self.root/'a').mkdir();(self.root/'a'/'x').touch();(self.root/'b').touch()
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):list(_support.walk(fd,max_entries=2))
        with mock.patch.object(_support.os,'name','unsupported'):
            with self.assertRaises(_support.InputError):_support._flags()

if __name__=="__main__":unittest.main()
