from unittest import TestCase
from certau.source.base import StixSourceItem
from certau.source.taxii import TaxiiContentBlockSource
import os

class SillyStixSourceItem(StixSourceItem):
    def io(self):
	pass

    def file_name(self):
	return "silly_name.stix.xml"

class TestStixSourceItem(TestCase):
    """
    Responsible for testing certau.source.base.StixSourceItem
    """

    def test_constructor(self):
       ssi = SillyStixSourceItem({})
       self.assertIsNotNone(ssi)
       self.assertIsNone(ssi.stix_package)

    def silent_delete_file(self, filename):
       try:
          if filename:
 	      os.remove(filename)
       except Exception:
          pass  # no file to delete is ok
       try: 
          os.stat(filename)
          raise Exception("File still exists despite deletion: {}".format(filename))
       except Exception:
          pass 

    def test_save(self):
       ssi = SillyStixSourceItem({})
       silly_folder = "/tmp"
       silly_filename = ssi.file_name()
       expected_file = "{}/{}".format(silly_folder, silly_filename)
       # ensure file is not present
       self.silent_delete_file(expected_file)
       ssi.save(silly_folder)
       self.assertIsNotNone(os.stat(expected_file))
       self.silent_delete_file(expected_file) 
       with self.assertRaises(OSError): # no such file or directory is expected
           os.stat(expected_file)


class TestTaxiiSource(TestCase):
    def test_taxii_content_block_source(self):
       src = TaxiiContentBlockSource([], {})
       self.assertIsNotNone(src)
       items = src.source_items()
       self.assertIsNotNone(items)
       cnt = 0
       for item in items:
           cnt += 1
       self.assertEqual(cnt, 0)
