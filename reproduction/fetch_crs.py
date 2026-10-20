"""Fetch only pinned upstream CRS setup/rule assets. Never extract regression fixtures."""
import hashlib,io,json,sys,tarfile,urllib.request
from pathlib import Path

target=Path(sys.argv[1])
pins=json.loads(Path(__file__).with_name('crs-file-sha256.json').read_text())
if all((target/name).is_file() and hashlib.sha256((target/name).read_bytes()).hexdigest()==digest for name,digest in pins.items()):
    print('CRS files already match pinned hashes.');raise SystemExit(0)
url='https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.tar.gz'
request=urllib.request.Request(url,headers={'User-Agent':'T10-Reproduction/1.0'})
with urllib.request.urlopen(request,timeout=90) as response:
    archive=response.read(30*1024*1024+1)
if len(archive)>30*1024*1024:raise SystemExit('Archive unexpectedly large')
pending={}
with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
    for member in tar.getmembers():
        if not member.isfile() or member.issym() or member.islnk():continue
        parts=Path(member.name).parts
        if len(parts)<2:continue
        name=Path(*parts[1:]).as_posix()
        if name not in pins:continue
        data=tar.extractfile(member).read()
        if hashlib.sha256(data).hexdigest()!=pins[name]:raise SystemExit('CRS hash mismatch: '+name)
        pending[name]=data
if set(pending)!=set(pins):raise SystemExit('Pinned CRS files missing from archive')
for name,data in pending.items():
    path=(target/name).resolve()
    if not path.is_relative_to(target.resolve()):raise SystemExit('Invalid destination')
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
print('Fetched and verified CRS files:',len(pending))
