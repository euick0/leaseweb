"""Real repository layouts and real registries: pom.xml builds, requirements /
pyproject / lock files, go.mod, and verified downloads. No network: registries
are faked."""
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from agent import config, inventory, pipeline, registry, vetter
from agent.drivers import golang, pom
from agent.drivers.base import DriverError
from agent.drivers.golang import GoEcosystem
from agent.drivers.maven import MavenEcosystem
from agent.drivers.pypi import PypiEcosystem
from agent.schemas import Component

ROOT_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>shop</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules><module>web</module></modules>
  <properties>
    <jackson.version>2.13.3</jackson.version>
    <fileupload.version>1.4</fileupload.version>
    <shared.version>3.1</shared.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-core</artifactId>
        <version>${jackson.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>commons-fileupload</groupId>
      <artifactId>commons-fileupload</artifactId>
      <version>${fileupload.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-shade-plugin</artifactId>
        <version>${shared.version}</version>
        <dependencies>
          <dependency>
            <groupId>org.ow2.asm</groupId>
            <artifactId>asm</artifactId>
            <version>9.0</version>
          </dependency>
        </dependencies>
      </plugin>
    </plugins>
  </build>
</project>
"""

WEB_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent><groupId>com.acme</groupId><artifactId>shop</artifactId><version>1.0.0</version></parent>
    <artifactId>web</artifactId>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>core</artifactId>
            <version>1.0.0</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-core</artifactId>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>${jackson.version}</version>
        </dependency>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>${shared.version}</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
            <exclusions>
                <exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion>
            </exclusions>
        </dependency>
    </dependencies>
</project>
"""


@pytest.fixture
def maven_repo(tmp_path):
    (tmp_path / "pom.xml").write_text(ROOT_POM)
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "pom.xml").write_text(WEB_POM)
    return tmp_path


def maven(g, a, v):
    return Component(ecosystem="maven", group=g, name=a, version=v)


# --------------------------------------------------------------------- maven

def test_pom_inventory_resolves_properties_and_management(maven_repo):
    found = {(c.coordinate, c.version) for c in MavenEcosystem().components(maven_repo)}
    assert found == {("commons-fileupload:commons-fileupload", "1.4"),
                     ("com.fasterxml.jackson.core:jackson-core", "2.13.3"),        # version from dependencyManagement
                     ("com.fasterxml.jackson.core:jackson-databind", "2.13.3"),
                     ("commons-collections:commons-collections", "3.1"),
                     ("org.apache.logging.log4j:log4j-core", "2.14.1")}
    # not listed: junit (test scope), asm (a build plugin's dependency), com.acme:core (the build's own module)


def test_literal_version_is_replaced_in_place(maven_repo):
    before = (maven_repo / "web/pom.xml").read_text()
    assert MavenEcosystem().bump(maven_repo, maven("org.apache.logging.log4j", "log4j-core", "2.14.1"), "2.17.1") \
        == ["web/pom.xml"]
    after = (maven_repo / "web/pom.xml").read_text()
    assert after == before.replace("<version>2.14.1</version>", "<version>2.17.1</version>")   # one line, nothing else


def test_another_version_of_the_same_artifact_is_left_alone(maven_repo):
    changed = MavenEcosystem().bump(maven_repo, maven("org.apache.logging.log4j", "log4j-core", "2.7"), "2.17.1")
    assert "2.14.1" in (maven_repo / "web/pom.xml").read_text()           # the 2.14.1 occurrence is another match
    assert changed == ["pom.xml"]                                          # 2.7 is not declared: managed override


def test_property_owned_by_one_artifact_is_changed(maven_repo):
    MavenEcosystem().bump(maven_repo, maven("commons-fileupload", "commons-fileupload", "1.4"), "1.6.0")
    assert "<fileupload.version>1.6.0</fileupload.version>" in (maven_repo / "pom.xml").read_text()


def test_property_shared_with_unrelated_use_pins_only_this_artifact(maven_repo):
    MavenEcosystem().bump(maven_repo, maven("commons-collections", "commons-collections", "3.1"), "3.2.2")
    assert "<shared.version>3.1</shared.version>" in (maven_repo / "pom.xml").read_text()   # the plugin keeps 3.1
    web = (maven_repo / "web/pom.xml").read_text()
    assert "<artifactId>commons-collections</artifactId>\n            <version>3.2.2</version>" in web


def test_a_release_train_moves_and_is_vetted_together(maven_repo):
    eco = MavenEcosystem()
    databind = maven("com.fasterxml.jackson.core", "jackson-databind", "2.13.3")
    assert eco.lockstep(maven_repo, databind, "2.18.3") == [("com.fasterxml.jackson.core:jackson-core", "2.18.3")]
    assert eco.bump(maven_repo, databind, "2.18.3") == ["pom.xml"]
    assert "<jackson.version>2.18.3</jackson.version>" in (maven_repo / "pom.xml").read_text()


def test_transitive_or_parent_managed_package_gets_a_management_override(maven_repo):
    MavenEcosystem().bump(maven_repo, maven("org.yaml", "snakeyaml", "1.33"), "2.2")
    text = (maven_repo / "pom.xml").read_text()
    entry = text[text.index("<dependencyManagement>"):text.index("</dependencyManagement>")]
    assert "<artifactId>snakeyaml</artifactId>" in entry and "<version>2.2</version>" in entry
    assert "\n      <dependency>\n        <groupId>org.yaml</groupId>" in entry      # the file's 2-space style
    assert {c.coordinate for c in pom.components(maven_repo)} >= {"commons-fileupload:commons-fileupload"}


def test_a_pom_without_dependency_management_gets_one(tmp_path):
    (tmp_path / "pom.xml").write_text('<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
                                      "  <groupId>a</groupId><artifactId>b</artifactId><version>1</version>\n"
                                      "  <dependencies>\n  </dependencies>\n</project>\n")
    MavenEcosystem().bump(tmp_path, maven("org.yaml", "snakeyaml", "1.33"), "2.2")
    text = (tmp_path / "pom.xml").read_text()
    assert text.index("<dependencyManagement>") < text.index("<dependencies>\n  </dependencies>")
    assert pom.components(tmp_path) == []                                 # managed, not declared


# ---------------------------------------------------------------------- pypi

def test_requirements_pins_keep_extras_markers_and_comments(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# app\nDjango==4.2  # web\nrequests[socks]>=2.0 ; python_version >= '3.8'\n-r base.txt\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest==7.0\n")
    eco = PypiEcosystem()
    assert [(c.name, c.version) for c in eco.components(tmp_path)] == [("django", "4.2")]   # dev file skipped
    eco.bump(tmp_path, Component(ecosystem="pypi", name="django", version="4.2"), "4.2.26")
    eco.bump(tmp_path, Component(ecosystem="pypi", name="requests", version="2.0"), "2.32.4")
    eco.bump(tmp_path, Component(ecosystem="pypi", name="urllib3", version="1.26.0"), "2.5.0")    # transitive
    assert (tmp_path / "requirements.txt").read_text().splitlines() == [
        "# app", "Django==4.2.26  # web", "requests[socks]==2.32.4; python_version >= '3.8'", "-r base.txt",
        "urllib3==2.5.0  # PatchPilot: pinned to the vetted fix"]


def test_pyproject_dependencies_are_pinned(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["flask==2.0.0", "jinja2>=3"]\n')
    eco = PypiEcosystem()
    assert [(c.name, c.version) for c in eco.components(tmp_path)] == [("flask", "2.0.0")]
    assert eco.bump(tmp_path, Component(ecosystem="pypi", name="Jinja2", version="3.0"), "3.1.6") == ["pyproject.toml"]
    assert '"jinja2==3.1.6"' in (tmp_path / "pyproject.toml").read_text()
    with pytest.raises(DriverError, match="not declared"):
        eco.bump(tmp_path, Component(ecosystem="pypi", name="urllib3", version="1"), "2.5.0")


@pytest.mark.parametrize("name,content", [
    ("poetry.lock", '[[package]]\nname = "Django"\nversion = "4.2"\n\n[[package]]\nname = "sqlparse"\nversion = "0.4.0"\n'),
    ("uv.lock", '[[package]]\nname = "app"\nversion = "0.1"\nsource = { virtual = "." }\n\n'
                '[[package]]\nname = "django"\nversion = "4.2"\n\n[[package]]\nname = "sqlparse"\nversion = "0.4.0"\n'),
    ("Pipfile.lock", json.dumps({"default": {"django": {"version": "==4.2"}, "sqlparse": {"version": "==0.4.0"}},
                                 "develop": {"pytest": {"version": "==7.0"}}})),
])
def test_lock_files_list_transitive_packages(tmp_path, name, content):
    (tmp_path / name).write_text(content)
    assert {(c.name, c.version) for c in PypiEcosystem().components(tmp_path)} == {("django", "4.2"), ("sqlparse", "0.4.0")}


# ------------------------------------------------------------------------ go

GO_MOD = """module github.com/acme/shop

go 1.22

require github.com/gorilla/mux v1.8.0

require (
\tgolang.org/x/net v0.52.0 // indirect
\tgoogle.golang.org/grpc v1.79.3
)

replace example.com/old => example.com/new v1.0.0
"""


def test_go_mod_inventory_without_the_v(tmp_path):
    (tmp_path / "go.mod").write_text(GO_MOD)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "go.mod").write_text("module vendored\nrequire bad.example v9.9.9\n")
    found = {(c.name, c.version) for c in GoEcosystem().components(tmp_path)}
    assert found == {("github.com/gorilla/mux", "1.8.0"), ("golang.org/x/net", "0.52.0"),
                     ("google.golang.org/grpc", "1.79.3")}


def test_go_bump_without_the_toolchain_edits_go_mod_and_go_sum(tmp_path, monkeypatch):
    (tmp_path / "go.mod").write_text(GO_MOD)
    (tmp_path / "go.sum").write_text("golang.org/x/net v0.52.0 h1:old=\n")
    monkeypatch.setattr(golang.shutil, "which", lambda tool: None)
    monkeypatch.setattr(registry, "go_sums", lambda m, v: ("h1:zip=", "h1:mod="))
    eco = GoEcosystem()
    net = Component(ecosystem="go", name="golang.org/x/net", version="0.52.0")
    assert eco.lockstep(tmp_path, net, "0.60.0") == []                  # no toolchain: only the module moves
    assert eco.bump(tmp_path, net, "0.60.0") == ["go.mod", "go.sum"]
    assert "\tgolang.org/x/net v0.60.0 // indirect" in (tmp_path / "go.mod").read_text()
    assert (tmp_path / "go.sum").read_text().splitlines() == [
        "golang.org/x/net v0.52.0 h1:old=", "golang.org/x/net v0.60.0 h1:zip=", "golang.org/x/net v0.60.0/go.mod h1:mod="]
    assert eco.bump(tmp_path, net, "0.60.0") == []                      # already raised: nothing to do
    with pytest.raises(DriverError):
        eco.bump(tmp_path, Component(ecosystem="go", name="example.com/none", version="1.0.0"), "1.0.1")


def test_go_module_zip_is_its_own_source(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("golang.org/x/net@v0.60.0/go.mod", "module golang.org/x/net\nrequire golang.org/x/text v0.42.0\n")
        zf.writestr("golang.org/x/net@v0.60.0/http2/server.go", "package http2\nfunc init() {}\n")
        zf.writestr("golang.org/x/net@v0.60.0/http2/server_test.go", "package http2\n")
        zf.writestr("golang.org/x/net@v0.60.0/http2/testdata/x.go", "package x\n")
    (tmp_path / "m.zip").write_bytes(buf.getvalue())
    eco = GoEcosystem()
    assert set(eco.sources(tmp_path / "m.zip")) == {"go.mod", "http2/server.go"}     # tests never ship
    assert eco.load_time_lines("http2/server.go", ["func init() {"], []) == ["func init() {"]
    expected = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(
        (n, zipfile.ZipFile(buf).read(n)) for n in zipfile.ZipFile(buf).namelist()))
    import base64
    assert registry.go_zip_h1(buf.getvalue()) == "h1:" + base64.b64encode(hashlib.sha256(expected.encode()).digest()).decode()


def test_syft_go_modules_drop_the_v_and_skip_the_main_module():
    doc = {"artifacts": [{"type": "go-module", "name": "golang.org/x/net", "version": "v0.52.0"},
                         {"type": "go-module", "name": "github.com/acme/shop", "version": "(devel)"},
                         {"type": "go-module", "name": "stdlib", "version": "go1.22.1"}]}
    assert [(c.ecosystem, c.name, c.version) for c in inventory.parse_syft(doc)] == [("go", "golang.org/x/net", "0.52.0")]


# ------------------------------------------------------------------ registry

class FakeHTTP:
    def __init__(self, files: dict):
        self.files, self.urls = files, []

    def __call__(self, url, headers=None, timeout=None):
        self.urls.append(url)
        body = self.files.get(url)
        return type("R", (), {"status_code": 200 if body is not None else 404,
                              "content": body if isinstance(body, bytes) else b"",
                              "text": body if isinstance(body, str) else "",
                              "json": lambda self: json.loads(body)})()


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ARTIFACTS", tmp_path / "artifacts")
    monkeypatch.setattr(config, "CHECKSUMS", tmp_path / "checksums.lock")
    return tmp_path


def test_maven_release_is_downloaded_verified_and_recorded(store, monkeypatch):
    jar, src = b"jar-bytes", b"src-bytes"
    base = "https://repo1.maven.org/maven2/org/yaml/snakeyaml/2.2"
    http = FakeHTTP({f"{base}/snakeyaml-2.2.jar": jar, f"{base}/snakeyaml-2.2.jar.sha1": hashlib.sha1(jar).hexdigest(),
                     f"{base}/snakeyaml-2.2-sources.jar": src,
                     f"{base}/snakeyaml-2.2-sources.jar.sha256": hashlib.sha256(src).hexdigest() + "  file"})
    monkeypatch.setattr(registry.requests, "get", http)
    comp = maven("org.yaml", "snakeyaml", "1.33")
    assert registry.fetch(comp, "2.2") == ["snakeyaml-2.2.jar", "snakeyaml-2.2-sources.jar"]
    lock = json.loads(config.CHECKSUMS.read_text())
    assert lock["maven/snakeyaml/2.2/snakeyaml-2.2.jar"] == hashlib.sha256(jar).hexdigest()
    assert registry.fetch(comp, "2.2") == []                                # already in the store

    http.files[f"{base}/snakeyaml-2.2.jar.sha1"] = "0" * 40                  # the registry and the file disagree
    (config.ARTIFACTS / "maven/snakeyaml/2.2/snakeyaml-2.2.jar").unlink()
    with pytest.raises(registry.FetchError, match="does not match the published"):
        registry.fetch(comp, "2.2")


def test_pypi_release_needs_a_source_distribution(store, monkeypatch):
    wheel, sdist = b"wheel", b"sdist"
    meta = {"urls": [
        {"packagetype": "bdist_wheel", "filename": "pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "url": "u/plat",
         "digests": {"sha256": "x"}},
        {"packagetype": "bdist_wheel", "filename": "pkg-1.0-py3-none-any.whl", "url": "u/whl",
         "digests": {"sha256": hashlib.sha256(wheel).hexdigest()}},
        {"packagetype": "sdist", "filename": "pkg-1.0.tar.gz", "url": "u/sdist",
         "digests": {"sha256": hashlib.sha256(sdist).hexdigest()}}]}
    http = FakeHTTP({"https://pypi.org/pypi/pkg/1.0/json": json.dumps(meta), "u/whl": wheel, "u/sdist": sdist})
    monkeypatch.setattr(registry.requests, "get", http)
    assert registry.fetch(Component(ecosystem="pypi", name="pkg", version="0.9"), "1.0") == \
        ["pkg-1.0-py3-none-any.whl", "pkg-1.0.tar.gz"]                       # the pure wheel, not the platform one
    w, s = PypiEcosystem().artifacts("pkg", "1.0")
    assert (w.name, s.name) == ("pkg-1.0-py3-none-any.whl", "pkg-1.0.tar.gz")

    meta["urls"] = meta["urls"][:2]
    http.files["https://pypi.org/pypi/pkg/2.0/json"] = json.dumps(meta)
    with pytest.raises(registry.FetchError, match="no source distribution"):
        registry.fetch(Component(ecosystem="pypi", name="pkg", version="1.0"), "2.0")


def test_a_release_that_cannot_be_fetched_is_unreviewed_not_malicious(store):
    res = vetter.vet({"id": "x"}, MavenEcosystem(), "nothing-here", "1.0", "1.1", lambda *a: None)
    assert res.verdict == "unreviewed" and "not vetted" in res.reasons[-1]


# ------------------------------------------------------------------ pipeline

def test_pipeline_vets_the_whole_family_and_the_change_moves_nothing_else(maven_repo, monkeypatch):
    """_bump_set on a real pom.xml build: databind's fix moves jackson-core too (shared
    property), both are listed for vetting, and the applied change moves exactly those."""
    from agent import fleet
    from agent.schemas import Workload
    eco = MavenEcosystem()
    src = type("Src", (), {"path": maven_repo})()
    fl = type("Fl", (), {"source": lambda self, wl: src, "ecosystem": lambda self, name: eco})()
    wl = Workload(id="eu/shop/web", name="web", target="eu", target_kind="kubernetes", provider="p", image="i",
                  internet_exposed=True, exposure="lb")
    databind = maven("com.fasterxml.jackson.core", "jackson-databind", "2.13.3")
    bump = pipeline._bump_set(fl, {"id": "GHSA-x"}, wl, databind, "2.18.3")
    assert [(c.coordinate, c.version, t) for c, t in bump] == [
        ("com.fasterxml.jackson.core:jackson-databind", "2.13.3", "2.18.3"),
        ("com.fasterxml.jackson.core:jackson-core", "2.13.3", "2.18.3")]
    before = eco.components(maven_repo)
    for c, t in bump:
        eco.bump(maven_repo, c, t)
    assert pipeline._unvetted_changes(before, eco.components(maven_repo), bump) == []
    # vetting databind alone would have been caught
    assert pipeline._unvetted_changes(before, eco.components(maven_repo), bump[:1]) == \
        ["com.fasterxml.jackson.core:jackson-core 2.18.3"]


def test_a_fix_that_moves_unvetted_packages_is_caught():
    net = Component(ecosystem="go", name="golang.org/x/net", version="0.52.0")
    sys_ = Component(ecosystem="go", name="golang.org/x/sys", version="0.43.0")
    after = [net.model_copy(update={"version": "0.60.0"}), sys_.model_copy(update={"version": "0.48.0"})]
    assert pipeline._unvetted_changes([net, sys_], after, [(net, "0.60.0")]) == ["golang.org/x/sys 0.48.0"]
    assert pipeline._unvetted_changes([net, sys_], after, [(net, "0.60.0"), (sys_, "0.48.0")]) == []
