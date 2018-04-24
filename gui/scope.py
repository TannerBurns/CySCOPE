import re
import binascii
import hashlib
import magic
import ssdeep
import pefile
import json
import string

from datetime import datetime
from M2Crypto import SMIME, X509, BIO, m2

#import vtow as vt
  
def convert_to_printable(s):
    return str(s.decode('utf-8'))

def convert(input):
	 if isinstance(input, dict):
		 return {convert(key): convert(value) for key, value in input.iteritems()}
	 elif isinstance(input, list):
		 return [convert(element) for element in input]
	 elif isinstance(input, unicode):
		 return input.encode('utf-8')
	 else:
		 return input

#updated for python3
def get_strings(filename):
    if filename:
        with open(filename, encoding="utf-8", errors="ignore") as fin:
            fraw = fin.read()

        strings = re.findall('[^\x00-\x1F\x7F-\xFF]{4,}',fraw)
        urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',fraw)
        return {"strings": strings, "urls": urls}

#updated for python3
def get_hex(filename):
    with open(filename,'rb') as fin:
        data=binascii.hexlify(fin.read()).upper().decode("utf-8")
    
    holder = []
    for i in range(0, len(data), 2):
        hd = "{}{}".format(data[i],data[i+1])
        if ord(chr(int(hd, 16))) > 126 or ord(chr(int(hd, 16))) < 32:
            hd = '.'
        else:
            hd = chr(int(hd, 16))
        holder.append(hd)
    holder = ' '.join(holder)


    i=0
    linehexcount=0
    hexdump=[]
    for j in range(32,len(data)+32,32):
        line1 = data[i:i+32]
        line2 = holder[i:i+32]
        counter='{0:07X}'.format(linehexcount)
        nline='{}  {:24}  {:48}'.format(counter, line1, line2)
        hexdump.append(nline)

        i=j
        linehexcount+=16
    return hexdump

def get_sha256(filename):
    with open(filename,'rb')as fs:
        pesha=hashlib.sha256()
        pesha.update(fs.read())
        return str(pesha.hexdigest()).upper()

def get_sha1(filename):
    with open(filename,'rb')as fs:
        pesha=hashlib.sha1()
        pesha.update(fs.read())
        return str(pesha.hexdigest()).upper()

def get_md5(filename):
    with open(filename,'rb')as fs:
        pesha=hashlib.md5()
        pesha.update(fs.read())
        return str(pesha.hexdigest()).upper()

def get_file_magic(path):
    m = magic.open(magic.MAGIC_MIME)
    m.load()
    return str(m.file(path))

def get_ssdeep(path):
    try:
        with open(path,'rb') as fin:
            fraw = fin.read()
        ssd=ssdeep.hash(fraw)
        return ssd
    except Exception as err:
        print('SSDEEP ERRROR: {}'.format(err))
        return None

def get_hashes(path):
    return {"md5": get_md5(path), "sha1": get_sha1(path), "sha256": get_sha256(path), "ssdeep": get_ssdeep(path)}

#updated for python3
def get_sections(pe):
    header='{:<8} {:>10} {:>10} {:>10} {:>10} {:^30} \t{:<10}\n'.format('Section','VirtSize','VirtAddr','PhysSize','PhysAddr','MD5','Characteristics')
    data=[header]
    for section in pe.sections:
        perm=None
        if '0x2' in str(section).split()[-1]:
            perm='{}MEM_EXECUTE\n'
        elif '0x4' in str(section).split()[-1]:
            perm='{}MEM_READ\n'
        elif '0x8' in str(section).split()[-1]:
            perm='{}MEM_WRITE\n'
        elif '0x6' in str(section).split()[-1]:
            perm='{}MEM_READ|MEM_EXECUTE\n'
        elif '0xA' in str(section).split()[-1]:
            perm='{}MEM_WRITE|MEM_EXECUTE\n'
        elif '0xC' in str(section).split()[-1]:
            perm='{}MEM_READ|MEM_WRITE\n'
        elif '0xE' in str(section).split()[-1]:
            perm='{}MEM_READ|MEM_WRITE|MEM_EXECUTE\n'
        
        if perm:
            if '020' in str(section).split()[-1] or '060' in str(section).split()[-1] or '0A0' in str(section).split()[-1]:
                perm=perm.format('CODE|')
            else:
                perm=perm.format('')

        data.append('{:<8} {:>10} {:>10} {:>10} {:>10} {:>30} {:<10}'.format(section.Name.decode("utf-8"),str(hex(int(section.Misc_VirtualSize))),str(hex(int(section.VirtualAddress))),str(hex(int(section.Misc_PhysicalAddress))),str(hex(int(section.PointerToRawData))),str(section.get_hash_md5()),perm))

    return data

class Imports:
    def __init__(self):
        self.dll_map = {'functions':{},'urls':{}}
        self.init_dll_map()
        
    def init_dll_map(self):
        with open('gui/dbs/msdn_imports.txt') as fin:
            raw=fin.read()
        raw=raw.split('\n\n')
        l1=raw[0].split('\n')
        l2=raw[1].split('\n')
        for i in l1:
            try:
                v='msdn_'+i.strip('[').split(']')[0]
                k=i.strip('[').split(']')[1]
                self.dll_map['functions'][k]=v
            except Exception as err:
                pass
        for j in l2:
            try:
                k=j.split()[0]
                v=j.split()[1]
                self.dll_map['urls'][k]=v
            except:
                pass
    
    def link_imports(self,imp):
        if imp:
            if imp in self.dll_map['functions']:
                val=self.dll_map['functions'][imp]
                return '<a href="{}" style="color:#3366ff;">{}</a>'.format(self.dll_map['urls'][val],imp)
            else:
                return '<span>{}</span>'.format(imp)

    def get_imports(self,filename):
        try:
            pe = pefile.PE(filename, fast_load=True)
            pe.parse_data_directories( directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        except:
            return None
        try:
            imports=[]
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode('utf-8'))
            pe.close()
            return imports
        except Exception:
            pe.close()
            return None

def get_exports(filename):
    try:
        pe = pefile.PE(filename, fast_load=True)
        pe.parse_data_directories( directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    except:
        return None
    try:
        exports=[]
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append('{}: {}'.format(exp.name.decode('utf-8'),exp.ordinal))
        pe.close()
        return exports
    except:
        pe.close()
        return None

def get_imphash(filename):
    try:
        pe = pefile.PE(filename, fast_load=True)
        pe.parse_data_directories( directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    except:
        return None
    try:
        imphash = pe.get_imphash()
        pe.close()
        return str(imphash)
    except:
        pe.close()
        return None

def get_dsig(pe):
    class Cert():
        def __init__(self,subject=None,issuer=None,adate=None,bdate=None,serial=None):
            def validity():
                vdate=datetime.strptime(self.adate, '%b %d %H:%M:%S %Y %Z')
                if vdate>datetime.now():
                    return True
                else:
                    return False

            self.subject=subject
            self.issuer=issuer
            self.adate=adate
            self.bdate=bdate
            self.serial=serial
            self.valid=validity()

        
        def readable(self):
            return 'Subject: {}\n\nIssuer: {}\n\nValid Until: {}\n\nSigned Date: {}\n\nSerial: {}'.format(self.subject,self.issuer,self.adate,self.bdate,self.serial)

    def digest_dsig(dsig):
        data=BIO.MemoryBuffer(dsig)
        mime_obj=SMIME.PKCS7(m2.pkcs7_read_bio_der(data._ptr()))
        signs=mime_obj.get0_signers(X509.X509_Stack())
        certs=[]
        for cert in signs:
            ddsig={}
            cert_spl=(cert.as_text()).split('\n')
            for x, l in enumerate(cert_spl):
                if '        Subject:' in l:
                    ddsig['subject']=l.lstrip('        Subject:')
                elif '        Issuer:' in l:
                    ddsig['issuer']=l.lstrip('        Issuer:')
                elif '        Validity' in l:
                    bdate=cert_spl[x+1].lstrip('        Not before')[8:]
                    adate=cert_spl[x+2].lstrip('        Not After')[2:]
                    ddsig['bdate']=bdate
                    ddsig['adate']=adate
                elif l.startswith('        Serial Number: '):
                    hcert=cert_spl[x].split(':')[1].split()[1].strip('(0x').strip(')')
                    if len(hcert)%2 != 0:
                        hcert='0{}'.format(hcert)
                    ser=':'.join(a+b for a,b in zip(iter(hcert),iter(hcert)))
                    ddsig['serial']=ser
                elif '        Serial Number:' in l:
                    scert=cert_spl[x+1].strip()
                    ddsig['serial']=scert
            c=Cert(ddsig['subject'],ddsig['issuer'],ddsig['adate'],ddsig['bdate'],ddsig['serial'])
            certs.append(c)
        return certs

    try:
        vstart=pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        vend=pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        if vstart==0:
            return None
        bdsig=bytes(pe.write()[vstart+8:(vstart+vend)])
        return digest_dsig(bdsig)
    except Exception as err:
        return None

def get_stringtable(filename):
    pe = pefile.PE(filename, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

    ret = []
    if hasattr(pe, 'VS_VERSIONINFO'):
        if hasattr(pe, 'FileInfo'):
            for entry in pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for ste in st.entries.items():
                            ret.append('{}: {}'.format(convert_to_printable(ste[0]),convert_to_printable(ste[1])))
                elif hasattr(entry, 'Var'):
                    for vent in entry.Var:
                        if hasattr(vent, 'entry'):
                            somevar = next(iter(vent.entry.items()))
                            ret.append('{}: {}'.format(somevar[0].decode("utf-8"),somevar[1]))
    
    return '\n'.join(ret)

    
def get_checksum(pe):
    try:
        set_checksum = pe.OPTIONAL_HEADER.CheckSum
        generated_checksum = pe.generate_checksum()
        if set_checksum == 0:
            return '  NOT SET'
        elif set_checksum == generated_checksum:
            return '  SET: MATCHING'
        elif set_checksum != generated_checksum:
            return '  SET: NOT MATCHING'
    except:
        return None

def get_vtreport(vtkey=None,sha256=None):
    if sha256:
        vtobj=vt.vt_report(vtkey=vtkey,sha256=sha256)
        if vtobj:
            data=vt.get_scan(vtobj)
            permalink = vtobj['permalink'] if 'permalink' in vtobj else None
            out1=vt.get_positives(vtobj)
            out2=json.dumps(data,sort_keys=True,indent=4, separators=(' ', ': ')).replace('{','').replace('}','').replace('[','').replace(']','').replace('"','').replace('\n\n','\n').split('\n')
            for i in range(0,len(out2)):
                if ' ' == out2[i].split(':')[-1]:
                    out2[i] = out2[i].replace(':','')
            return {"link": permalink, "pos": out1, "res": out2}
        else:
            return None
