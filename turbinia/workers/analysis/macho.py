"""Task for analysing Mach-O Information."""

import json
import lief
import os
import time

from asn1crypto import cms
from time import strftime
from turbinia import TurbiniaException
from typing import List

from plaso.analyzers.hashers import entropy
from plaso.analyzers.hashers import md5
from plaso.analyzers.hashers import sha256

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

class Architecture(object):
    def __init__(self):
        self.x86_64 = False
        self.arm64 = False

class Hashes(object):
    def __init__(self):
        self.sha256 = ""
        self.md5 = ""
        self.ssdeep = ""
        self.tlsh = ""
        self.symhash = ""

class Section(object):
    def __init__(self, flags: List[str]):
        self.name = ""
        self.entropy = 0
        self.address = ""
        self.size = ""
        self.offset = ""
        self.section_type = ""
        self.flags = flags

class Segment(object):
    def __init__(self, sections: List[Section]):
        #self.command = ""
        self.name = ""
        self.offset = ""
        self.size = 0
        self.vaddr = ""
        self.vsize = ""
        self.sections = sections

class ParsedBinary(object):
    def __init__(self, hashes: Hashes, segments: List[Segment], symbols: List[str]):
        self.entropy = 0
        self.size = 0
        self.fat_offset = 0
        self.magic = ""
        self.flags = 0
        self.hashes = hashes
        self.segments = segments
        self.symbols = symbols

class Export(object):
    def __init__(self):
        self.name = ""
        self.offset = ""

class ParsedFatBinary(object):
    def __init__(self, hashes: Hashes):
        self.size = 0
        self.entropy = 0
        self.hashes = hashes

class Import(object):
    def __init__(self):
        self.dylib = ""
        self.name = "" 

class Iocs(object):
    def __init__(self, domains: List[str], urls: List[str], ips: List[str]):
        self.domains = domains
        self.urls = urls
        self.ips = ips

class SignerInfo(object):
    def __init__(self):
        self.organization_name = ""
        self.organizational_unit_name = ""
        self.common_name = ""
        self.signing_time = ""
        self.cd_hash = ""
        self.message_digest = ""

class Signature(object):
    def __init__(self, signer_infos: List[SignerInfo]):
        self.signer_infos = signer_infos
        self.identifier = ""
        self.team_identifier = "not set"
        self.size = 0
        self.hash_type = ""
        self.hash_size = 0
        self.platform_identifier = 0
        self.pagesize = 0

class ParsedMacho(object):
  def __init__(self, signature: Signature, architecture: Architecture, iocs: Iocs, imports: List[Import], exports: List[Export], fat_binary: ParsedFatBinary, arm64: ParsedBinary, x86_64: ParsedBinary):
        self.request = ""
        self.evidence = ""
        self.source_path = ""
        self.source_type = ""
        self.processing_time = 0
        self.signature = signature
        self.architecture = architecture
        self.iocs = iocs
        self.imports = imports
        self.exports = exports
        self.fat_binary = fat_binary
        self.arm64 = arm64
        self.x86_64 = x86_64

class MachoAnalysisTask(TurbiniaTask):
  """Task to analyse Mach-O Information"""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  _MAGIC_MULTI_SIGNATURE = b'\xca\xfe\xba\xbe'
  _MAGIC_32_SIGNATURE    = b'\xce\xfa\xed\xfe'
  _MAGIC_64_SIGNATURE    = b'\xcf\xfa\xed\xfe'

  # Code signature constants
  # https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h
  _CSMAGIC_EMBEDDED_SIGNATURE = b'\xfa\xde\x0c\xc0' # embedded form of signature data
  _CSMAGIC_CODEDIRECTORY      = b'\xfa\xde\x0c\x02' # CodeDirectory blob
  _CSMAGIC_BLOBWRAPPER        = b'\xfa\xde\x0b\x01' # Wrapper blob used for CMS Signature, among other things

  # Slot numbers
  # https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h
  _CSSLOT_CODEDIRECTORY = b'\x00\x00\x00\x00' # Code Directory slot
  _CSSLOT_SIGNATURESLOT = b'\x00\x01\x00\x00' # CMS Signature slot

  def _GetDigest(self, hasher, data):
    """Executes a hasher and returns the digest.
    Args:
      hasher (BaseHasher): hasher to execute.
      data (bytestring) : data to be hashed.
     Returns:
      digest (str): digest returned by hasher.
    """
    hasher.Update(data)
    return hasher.GetStringDigest()

  def _GetSymhash(self, binary):
    """Retrieves Mach-O segment names.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
    Returns:
      symhash (str): symhash of the binary.
    """
    symbol_list = []
    for symbol in binary.imported_symbols:
      if symbol.type == 0 and symbol.origin == lief._lief.MachO.Symbol.ORIGIN.LC_SYMTAB:
        symbol_list.append(symbol.demangled_name)
    hasher = md5.MD5Hasher()
    hasher.Update(','.join(sorted(symbol_list)).encode())
    symhash = hasher.GetStringDigest()
    return symhash
  
  def _GetSections(self, segment, result):
    """Retrieves Mach-O segment section names.
    Args:
      segment (lief.MachO.SegmentCommand): segment to be parsed for sections.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      List[Sections]: Sections of the segments.
    """
    sections = []
    #result.log(f'----------- sections --------------')
    for sec in segment.sections:
      flags = []
      section = Section(flags)
      section.name = sec.name
      sections.append(section)
    #result.log(f'-----------------------------------')
    return sections

  def _GetSegments(self, binary, result):
    """Retrieves Mach-O segments.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      List[Segments]: List of the segments.
    """
    segments = []
    #result.log(f'----------- segments --------------')
    for seg in binary.segments:
      sections = self._GetSections(seg, result)
      segment = Segment(sections)
      segment.name = seg.name
      segment.offset = hex(seg.file_offset)
      segment.size = seg.file_size
      segment.vaddr = hex(seg.virtual_address)
      segment.vsize = hex(seg.virtual_size)
      segments.append(segment)
    #result.log(f'-----------------------------------')
    return segments

  def _GetSymbols(self, binary, result):
    """Retrieves Mach-O symbols.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      List[str]: List of the symbols.
    """
    symbols = []
    #result.log(f'----------- symbols --------------')
    for sym in binary.symbols:
      symbols.append(sym.demangled_name)
    #result.log(f'-----------------------------------')
    return symbols

  def _CSHashType(self, cs_hash_type):
    """Translates CS hash type to a string.
    Args:
      cs_hash_type (int): CS hash type.
    Returns:
      (str): CS hash type string.
    """
    if cs_hash_type == 1:
      return "SHA1"
    elif cs_hash_type == 2:
      return "SHA256"
    elif cs_hash_type == 3:
      return "SHA256_TRUNCATED"
    elif cs_hash_type == 4:
      return "SHA384"
    else:
      return ""

  def _ParseCodeSignature(self, code_signature, result):
    """Parses Mach-O code signature.
       Details about the code signature structure on GitHub
       https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L267
    Args:
      code_signature (lief.MachO.CodeSignature): code signature to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns: Signature or None if not found
    """
    signature = None
    signature_bytes = code_signature.content.tobytes()
    #result.log(f'code_signature.data_size = {code_signature.data_size}')
    #result.log(f'{signature_bytes.hex()}')
    #result.log(f'data_offset: {code_signature.data_offset}')
    #result.log(f'signature_bytes size: {len(signature_bytes)}')
    super_blob_magic = signature_bytes[0:4] # uint32_t magic
    if super_blob_magic == self._CSMAGIC_EMBEDDED_SIGNATURE:
      # SuperBlob called EmbeddedSignatureBlob found which contains the code signature data
      # struct EmbeddedSignatureBlob {
      #   uint32_t magic = 0xfade0cc0;
      #   uint32_t length;
      #   uint32_t count; // Count of contained blob entries
      #   IndexEntry entries[]; // Has `count` entries
      #   Blob blobs[]; // Has `count` blobs
      # }
      signature = Signature(signer_infos=[])
      result.log(f'*** found embedded signature ***')
      result.log(f'_CSSLOT_SIGNATURESLOT: {self._CSSLOT_SIGNATURESLOT}')
      super_blob_length = int.from_bytes(signature_bytes[4:8], "big") # uint32_t length
      generic_blob_count = int.from_bytes(signature_bytes[8:12], "big") # uint32_t count: Count of contained blob entries
      result.log(f'super_blob_length: ' + str(super_blob_length))
      result.log(f'generic_blob_count: ' + str(generic_blob_count))
      for i in range(generic_blob_count):
        # lets walk through the CS_BlobIndex index[] entries
        # https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L280C15-L280C22
        #ind = 'index_' + str(i)
        #result.log(f' {ind}')
        start_index_entry_type = 12 + i*8 # uint32_t type
        start_index_entry_offset = start_index_entry_type + 4 # uint32_t offset
        result.log(f' start_type:  {start_index_entry_type}')
        result.log(f' start_index_entry_offset: {start_index_entry_offset}')
        blob_index_type = signature_bytes[start_index_entry_type:start_index_entry_type+4]
        blob_index_offset = int.from_bytes(signature_bytes[start_index_entry_offset:start_index_entry_offset+4], "big")
        result.log(f'   type  : {blob_index_type}')
        result.log(f'   offset: {blob_index_offset}')
        generic_blob_magic = signature_bytes[blob_index_offset:blob_index_offset+4]
        generic_blob_length = int.from_bytes(signature_bytes[blob_index_offset+4:blob_index_offset+8], "big")
        result.log(f'     magic : {generic_blob_magic}')
        result.log(f'     length: {generic_blob_length}')
        if generic_blob_magic == self._CSMAGIC_CODEDIRECTORY and blob_index_type == self._CSSLOT_CODEDIRECTORY:
          # CodeDirectory is a Blob the describes the binary being signed
          result.log(f'     found CSMAGIC_CODEDIRECTORY (0xfade0c02) with Code Directory slot')
          code_directory = signature_bytes[blob_index_offset:blob_index_offset+generic_blob_length]
          cd_length = int.from_bytes(code_directory[4:8], "big")
          cd_hash_offset = int.from_bytes(code_directory[16:20], "big")
          cd_ident_offset = int.from_bytes(code_directory[20:24], "big")
          cd_hash_size = int.from_bytes(code_directory[36:37], "big")
          cd_hash_type = self._CSHashType(int.from_bytes(code_directory[37:38], "big"))
          cd_platform = int.from_bytes(code_directory[38:39], "big")
          cd_pagesize = 2**int.from_bytes(code_directory[39:40], "big")
          cd_team_id_offset = int.from_bytes(code_directory[48:52], "big")
          result.log(f'     cd_length         : {cd_length}')
          result.log(f'     cd_hash_offset    : {cd_hash_offset}')
          result.log(f'     cd_hash_size      : {cd_hash_size}')
          result.log(f'     cd_hash_type      : {cd_hash_type}')
          result.log(f'     cd_platform       : {cd_platform}')
          result.log(f'     cd_pagesize       : {cd_pagesize}')
          result.log(f'     cd_ident_offset   : {cd_ident_offset}')
          result.log(f'     cd_team_id_offset : {cd_team_id_offset}')
          signature.hash_type = cd_hash_type
          signature.hash_size = cd_hash_size
          signature.platform_identifier = cd_platform
          signature.pagesize = cd_pagesize
          if cd_ident_offset > 0:
            cd_ident = code_directory[cd_ident_offset:-1].split(b'\0')[0].decode()
            result.log(f'     cd_ident          : {cd_ident}')
            signature.identifier = cd_ident
          if cd_team_id_offset > 0:
            cd_team_id = code_directory[cd_team_id_offset:-1].split(b'\0')[0].decode()
            result.log(f'     cd_team_id        : {cd_team_id}')
            signature.team_identifier = cd_team_id
        elif generic_blob_magic == self._CSMAGIC_BLOBWRAPPER and blob_index_type == self._CSSLOT_SIGNATURESLOT:
          result.log(f'     found CSMAGIC_BLOBWRAPPER (0xfade0b01) with CMS Signature slot')
          signature.size = generic_blob_length
          blobwrapper_base = blob_index_offset+8
          cert = signature_bytes[blobwrapper_base:blobwrapper_base+generic_blob_length]
          #result.log(f'{cert}')
          content_info = cms.ContentInfo.load(cert)
          #result.log(f'content_info: {content_info.native}')
          if content_info['content_type'].native == 'signed_data':
            signed_data = content_info['content']
            #result.log(f'----------- signed data -----------')
            #result.log(f'signed_data: {signed_data.native}')
            #result.log(f'------------------------------------')
            signer_infos = signed_data['signer_infos']
            #encap_content_info = signed_data['encap_content_info']
            #result.log(f'----------- signer infos -----------')
            #result.log(f'signer_infos: {signer_infos.native}')
            #result.log(f'------------------------------------')
            #result.log(f'----------- signer infos -----------')
            for signer_info in signer_infos:
              signer = SignerInfo()
              #result.log(f'signer_info: {signer_info.native}')
              signed_attrs = signer_info['signed_attrs']
              result.log(f'signed_attrs: {signed_attrs.native}')
              for signed_attr in signed_attrs:
                #if signed_attrs['content_type'].native == 'data':
                #  signing_time = signed_attrs['signing_time']
                #result.log(f'signed_attr: {signed_attr.native}')
                signed_attr_type = signed_attr['type']
                result.log(f'signed_attr_type: {signed_attr_type.native}')
                signed_attr_values = signed_attr['values']
                result.log(f'signed_attr_values: {signed_attr_values.native}')
                if signed_attr_type.native == 'signing_time':
                  #result.log(f'signed_attr_values[0]: {signed_attr_values.native[0]}')
                  signer.signing_time = str(signed_attr_values.native[0])
                elif signed_attr_type.native == 'message_digest':
                  # https://forums.developer.apple.com/forums/thread/702351
                  result.log(f'signed_attr_values[0]: {signed_attr_values.native[0]}')
                  signer.message_digest = signed_attr_values.native[0].hex()
                  if len(signed_attr_values.native[0]) > 20:
                    signer.cd_hash = signed_attr_values.native[0][0:20].hex()
                  else:
                    signer.cd_hash = signed_attr_values.native[0].hex()
              sid = signer_info['sid']
              result.log(f'sid: {sid.native}')
              issuer = sid.chosen['issuer'].chosen
              result.log(f'issuer: {issuer.native}')
              for entry in issuer:
                # https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.4
                #result.log(f'entry: {entry.native}')
                for sub_entry in entry:
                  # https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
                  result.log(f'sub_entry: {sub_entry.native}')
                  name_type = sub_entry['type']
                  result.log(f'name_type: {name_type.native}')
                  val = sub_entry['value']
                  result.log(f'value: {val.native}')
                  if name_type.native == 'country_name':
                    signer.country_name = val.native
                  elif name_type.native == 'common_name':
                    signer.common_name = val.native
                  elif name_type.native == 'organization_name':
                    signer.organization_name = val.native
                  elif name_type.native == 'organizational_unit_name':
                    signer.organizational_unit_name = val.native
                  result.log(f'-----------------------------------')
              signature.signer_infos.append(signer)
    else:
      result.log(f'*** no embedded code signature detected ***')
    return signature
    
  def _ParseMachoFatBinary(self, macho_fd, evidence, result, macho_path, file_name):
    """Parses a Mach-O fat binary.
    Args:
      macho_fd (int): file descriptor to the fat binary.
      evidence (Evidence object):  The evidence to process
      result (TurbiniaTaskResult): The object to place task results into.
      macho_path (str): path to the fat binary.
      file_name (str): file name of the fat binary.
    Returns:
      FatBinary: the parsed Mach-O Fat Binary details.
    """
    result.log(f'---------- start fat binary ------------')
    macho_fd.seek(0)
    data = macho_fd.read()
    hashes = Hashes()
    hashes.md5 = self._GetDigest(md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(sha256.SHA256Hasher(), data)
    parsed_fat_binary = ParsedFatBinary(hashes)
    parsed_fat_binary.entropy = self._GetDigest(entropy.EntropyHasher(), data)
    fat_binary_stats = os.stat(macho_path)
    parsed_fat_binary.size = fat_binary_stats.st_size
    return parsed_fat_binary

  def _ParseMachoBinary(self, macho_fd, evidence, binary, result, file_name):
    """Parses a Mach-O binary.
    Args:
      macho_fd (int): file descriptor to the fat binary.
      evidence (Evidence object):  The evidence to process
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
      filename (str): file name of the binary.
    Returns:
      ParsedBinary: the parsed binary details.
    """
    result.log(f'------------ start binary --------------')
    fat_offset = binary.fat_offset
    binary_size = binary.original_size
    macho_fd.seek(fat_offset)
    data = macho_fd.read(binary_size)
    hashes = Hashes()
    hashes.md5 = self._GetDigest(md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(sha256.SHA256Hasher(), data)
    hashes.symhash = self._GetSymhash(binary)
    parsed_binary = ParsedBinary(hashes=hashes, segments=None, symbols=None)
    parsed_binary.entropy = self._GetDigest(entropy.EntropyHasher(), data)
    parsed_binary.size = binary_size
    parsed_binary.fat_offset = fat_offset
    parsed_binary.magic = hex(binary.header.magic.value)
    parsed_binary.flags = binary.header.flags
    parsed_binary.segments = self._GetSegments(binary, result)
    parsed_binary.symbols = self._GetSymbols(binary, result)
    if binary.has_code_signature:
      parsed_binary.signature = self._ParseCodeSignature(binary.code_signature, result)
    return parsed_binary

  def _WriteParsedMachoResults(self, file_name, parsed_macho):
    """Outputs the parsed Mach-O results.
    Args:
        parsed_macho(ParsedMacho): the parsed Mach-O details
    Returns:
        TurbiniaTaskResult object.
    """
    # Write the Mach-O Info to the output file.
    output_file_name = f'{file_name}.json'
    output_file_path=os.path.join(self.output_dir, output_file_name)
    with open(output_file_path, 'w') as fh:
      fh.write(f'{json.dumps(parsed_macho.__dict__, default=lambda o: o.__dict__, indent=2)}\n')
      fh.close()

  def _CurrentTimeMillis(self):
    return round(time.time() * 1000)

  def run(self, evidence, result):
    """Run the Mach-O worker.
    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    start_time = self._CurrentTimeMillis()
    output_file_name = 'macho_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # We output a report.
    output_evidence = ReportText(source_path=output_file_path)
    parsed_binaries = 0
    parsed_fat_binaries = 0

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(evidence.local_path):
      for file in files:
        macho_path = os.path.join(root, file)
        try:
          macho_binary = lief.MachO.parse(macho_path, config=lief.MachO.ParserConfig.quick)
          macho_fd = open(macho_path, 'rb')
        except IOError as e:
           # 'Error opening Mach-O file: {0:s}'.format(str(e)))
          break

        if isinstance(macho_binary, lief.MachO.FatBinary):
          architecture = Architecture()
          parsed_macho = ParsedMacho(signature=None, architecture=None, iocs=None, imports=None, exports=None, fat_binary=None, arm64=None, x86_64=None)
          parsed_macho.evidence = evidence.id
          parsed_macho.request = evidence.request_id
          parsed_macho.source_path = file
          parsed_macho.source_type = "file"
          parsed_macho.fat_binary = self._ParseMachoFatBinary(macho_fd, evidence, result, macho_path, file)
          parsed_fat_binaries += 1
          for binary in macho_binary:
            parsed_binary = self._ParseMachoBinary(macho_fd, evidence, binary, result, file)
            parsed_binaries += 1
            if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
              parsed_macho.arm64 = parsed_binary
              architecture.arm64 = True
            elif binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
              parsed_macho.x86_64 = parsed_binary
              architecture.x86_64 = True
          parsed_macho.architecture = architecture
          parsed_macho.processing_time = self._CurrentTimeMillis() - start_time
          self._WriteParsedMachoResults(file, parsed_macho)
          result.log(f'{json.dumps(parsed_macho.__dict__, default=lambda o: o.__dict__)}')
        elif isinstance(macho_binary, lief.MachO.Binary):
          #parsed_macho = self._ParseMachoBinary(macho_fd, evidence, macho_binary, result, file)
          parsed_binaries += 1
          #self._WriteParsedMachoResults(parsed_macho)
          #result.log(f'{json.dumps(parsed_macho.__dict__, default=lambda o: o.__dict__)}')
        macho_fd.close()
        result.log(f'------------------------')

    summary = f'Parsed {parsed_fat_binaries} lief.MachO.FatBinary and {parsed_binaries} lief.MachO.Binary'
    output_evidence.text_data = os.linesep.join(summary) 
    result.report_data = os.linesep.join(summary)
    result.report_priority = Priority.LOW

    # Write the Mach-O Info to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))
      fh.close()

    # Add the output evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)

    return result