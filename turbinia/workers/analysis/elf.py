"""Task for analysing ELF Information."""

import json
import os
import time

from time import strftime
from turbinia import TurbiniaException
from typing import List

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
    self.name = ""
    self.offset = ""
    self.size = ""
    self.vaddr = ""
    self.vsize = ""
    self.sections = sections


class Import(object):

  def __init__(self):
    self.name = ""
    self.size = ""
    self.offset = ""


class ParsedBinary(object):

  def __init__(
      self, hashes: Hashes, segments: List[Segment], symbols: List[str],
      imports: List[Import], flags: List[str]):
    self.entropy = 0
    self.size = 0
    self.fat_offset = 0
    self.magic = ""
    self.flags = flags
    self.hashes = hashes
    self.segments = segments
    self.symbols = symbols
    self.imports = imports


class Export(object):

  def __init__(self):
    self.name = ""
    self.offset = ""


class ParsedFatBinary(object):

  def __init__(self, hashes: Hashes):
    self.size = 0
    self.entropy = 0
    self.hashes = hashes


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
    self.cd_hash_calculated = ""


class ParsedElf(object):

  def __init__(
      self, signature: Signature, architecture: Architecture,
      exports: List[Export], fat_binary: ParsedFatBinary, arm64: ParsedBinary,
      x86_64: ParsedBinary):
    self.request = ""
    self.evidence = ""
    self.source_path = ""
    self.source_type = ""
    self.processing_time = 0
    self.signature = signature
    self.architecture = architecture
    self.exports = exports
    self.fat_binary = fat_binary
    self.arm64 = arm64
    self.x86_64 = x86_64


class ElfAnalysisTask(TurbiniaTask):
  """Task to analyse ELF Information"""

  REQUIRED_STATES = [state.ATTACHED, state.DECOMPRESSED]

  def __init__(self, *args, **kwargs):
    super(ElfAnalysisTask, self).__init__(*args, **kwargs)
    if TurbiniaTask.check_worker_role():
      try:
        import lief
        import tlsh
        import pyssdeep
        from plaso.analyzers.hashers import entropy
        from plaso.analyzers.hashers import md5
        from plaso.analyzers.hashers import sha256

        self._entropy = entropy
        self._lief = lief
        self._md5 = md5
        self._pyssdeep = pyssdeep
        self._sha256 = sha256
        self._tlsh = tlsh
      except ImportError as exception:
        message = f'Could not import libraries: {exception!s}'
        raise TurbiniaException(message)

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
    """Calculates Mach-O SymHash.
       https://www.anomali.com/fr/blog/symhash
    Args:
      binary (lief.ELF.Binary): binary to be parsed.
    Returns:
      symhash (str): symhash of the binary.
    """
    symbol_list = []
    for symbol in binary.imported_symbols:
      n_type = symbol.raw_type
      is_stab = n_type & self._N_STAB != 0
      is_external = n_type & self._N_EXT == self._N_EXT
      is_ntype = n_type & self._N_TYPE != 0
      if symbol.origin == self._lief._lief.MachO.Symbol.ORIGIN.LC_SYMTAB and not is_stab and is_external and not is_ntype:
        symbol_list.append(symbol.demangled_name)
    hasher = self._md5.MD5Hasher()
    hasher.Update(','.join(sorted(symbol_list)).encode())
    symhash = hasher.GetStringDigest()
    return symhash

  def _ParseElfBinary(self, elf_fd, evidence, binary, result, file_name):
    """Parses a ELF binary.
    Args:
      elf_fd (int): file descriptor to the binary.
      evidence (Evidence object):  The evidence to process
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
      filename (str): file name of the binary.
    Returns:
      ParsedBinary: the parsed binary details.
    """
    offset = 0
    binary_size = binary.virtual_size
    elf_fd.seek(offset)
    data = elf_fd.read(binary_size)
    hashes = Hashes()
    hashes.md5 = self._GetDigest(self._md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(self._sha256.SHA256Hasher(), data)
    #hashes.symhash = self._GetSymhash(binary)
    hashes.tlsh = self._tlsh.hash(data)
    hashes.ssdeep = self._pyssdeep.get_hash_buffer(data)
    parsed_binary = ParsedBinary(
        hashes=hashes, segments=None, symbols=None, imports=None, flags=None)
    parsed_binary.entropy = self._GetDigest(self._entropy.EntropyHasher(), data)
    parsed_binary.size = binary_size
    #parsed_binary.fat_offset = fat_offset
    #parsed_binary.magic = hex(binary.header.magic.value)
    #parsed_binary.segments = self._GetSegments(binary)
    #parsed_binary.symbols = self._GetSymbols(binary)
    #flags = []
    #for flag in binary.header.flags_list:
    #  flags.append(str(flag).split(".")[-1])
    #parsed_binary.flags = flags
    #imports = []
    #for lib in binary.libraries:
    #  imp = Import()
    #  imp.name = lib.name
    #  imp.size = hex(lib.size)
    #  imp.offset = hex(lib.command_offset)
    #  imports.append(imp)
    #parsed_binary.imports = imports

    #if binary.has_code_signature:
    #  parsed_binary.signature = self._ParseCodeSignature(
    #      binary.code_signature, result)
    #result.log(f'ParsedBinary: {parsed_binary}')
    return parsed_binary

  def _WriteParsedElfResults(self, file_name, parsed_elf, base_dir):
    """Outputs the parsed ELF results.
    Args:
        file_name(str): the name of the parsed ELF file
        parsed_elf(ParsedElf): the parsed ELF details
        base_dir(str): the base directory for the parsed ELF file
    Returns:
        TurbiniaTaskResult object.
    """
    # Write the ELF to the output file.
    output_file_name = f'{file_name}.json'
    output_dir_path = os.path.join(self.output_dir, 'reports', base_dir)
    if not os.path.exists(output_dir_path):
      os.makedirs(output_dir_path)
    output_file_path = os.path.join(output_dir_path, output_file_name)
    with open(output_file_path, 'w') as fh:
      # Plain vanilla json.dumps() doesn't support custom classes.
      # https://stackoverflow.com/questions/3768895/how-to-make-a-class-json-serializable
      fh.write(
          f'{json.dumps(parsed_elf.__dict__, default=lambda o: o.__dict__, indent=2)}\n'
      )
      fh.close()

  def _CurrentTimeMillis(self):
    return round(time.time() * 1000)
  
  def run(self, evidence, result):
    """Run the ELF worker.
    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    start_time = self._CurrentTimeMillis()
    output_file_name = 'elf_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # We output a report.
    output_evidence = ReportText(source_path=output_file_path)
    parsed_binaries = 0

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(evidence.local_path):
      for file in files:
        base_dir = os.path.relpath(root, evidence.local_path)
        elf_path = os.path.join(root, file)
        try:
          elf_binary = self._lief.ELF.parse(elf_path)
          elf_fd = open(elf_path, 'rb')
        except IOError as e:
          # 'Error opening ELF file: {0:s}'.format(str(e)))
          break

        if isinstance(elf_binary, self._lief.ELF.Binary):
          architecture = Architecture()
          parsed_elf = ParsedElf(
              signature=None, architecture=None, exports=None, fat_binary=None,
              arm64=None, x86_64=None)
          parsed_elf.evidence = evidence.id
          parsed_elf.request = evidence.request_id
          parsed_elf.source_path = file
          parsed_elf.source_type = "file"
          parsed_binaries += 1
          parsed_binary = self._ParseElfBinary(
                elf_fd, evidence, elf_binary, result, file)
          parsed_elf.x86_64 = parsed_binary
          parsed_elf.architecture = architecture
          parsed_elf.processing_time = self._CurrentTimeMillis() - start_time
          self._WriteParsedElfResults(file, parsed_elf, base_dir)
        else:
          result.log(
              f'Skipping unsupported format: {file}')
        elf_fd.close()

    summary = f'Parsed {parsed_binaries} lief.ELF.Binary'
    output_evidence.text_data = summary
    result.report_data = summary
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