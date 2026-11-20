"""Read and edit Maven pom.xml files the way a person would.

Reading uses the XML parser (properties, dependencyManagement and multi-module
builds resolved). Editing is textual and minimal, so a company's formatting,
comments and ordering survive and the pull request diff is one or two lines:

  1. the dependency (or its dependencyManagement entry) has a literal version: replace it
  2. the version is a ${property} only this artifact uses: change the property
  3. the property is shared with other artifacts: pin this artifact alone,
     so nothing that was not vetted moves
  4. the version comes from a parent or BOM, or the package is transitive:
     add an override to the root pom's <dependencyManagement>
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..schemas import Component

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
SKIP_DIRS = {"target", "node_modules", ".git", "build", "src"}
_PROP = re.compile(r"\$\{([^}]+)\}")


def poms(repo: Path) -> list[Path]:
    """Every pom.xml of the build, root first."""
    found = [p for p in repo.rglob("pom.xml") if not (SKIP_DIRS & set(p.relative_to(repo).parts[:-1]))]
    return sorted(found, key=lambda p: (len(p.relative_to(repo).parts), str(p)))


# --------------------------------------------------------------------- read

def _text(node, path: str) -> Optional[str]:
    el = node.find(path, NS)
    return el.text.strip() if el is not None and el.text else None


def _props(root) -> dict[str, str]:
    return {el.tag.split("}", 1)[1]: (el.text or "").strip() for el in root.findall("m:properties/*", NS)}


def resolve(value: Optional[str], props: dict[str, str]) -> Optional[str]:
    for _ in range(10):
        if not value or "${" not in value:
            return value
        value = _PROP.sub(lambda m: props.get(m.group(1), m.group(0)), value)
    return value


def _parse(path: Path):
    try:
        return ET.parse(path).getroot()
    except ET.ParseError:
        return None


def components(repo: Path) -> list[Component]:
    """Third-party dependencies the build declares (test scope and the build's own modules excluded)."""
    files = poms(repo)
    roots = {p: _parse(p) for p in files}
    roots = {p: r for p, r in roots.items() if r is not None}
    if not roots:
        return []
    root = roots[repo / "pom.xml"] if repo / "pom.xml" in roots else next(iter(roots.values()))
    version = _text(root, "m:version") or _text(root, "m:parent/m:version")
    base = {**_props(root), "project.version": version or "", "project.parent.version": version or ""}
    own = {(_text(r, "m:groupId") or _text(r, "m:parent/m:groupId"), _text(r, "m:artifactId"))
           for r in roots.values()}
    own_artifacts = {a for _, a in own}
    own_group = _text(root, "m:groupId") or _text(root, "m:parent/m:groupId")

    managed = {}
    for r in roots.values():
        props = {**base, **_props(r)}
        for el in r.findall("m:dependencyManagement/m:dependencies/m:dependency", NS):
            g, a, v = resolve(_text(el, "m:groupId"), props), _text(el, "m:artifactId"), resolve(_text(el, "m:version"), props)
            if g and a and v and "${" not in v:
                managed.setdefault((g, a), v)

    out, seen = [], set()
    for path, r in roots.items():
        props = {**base, **_props(r)}
        deps = (r.findall("m:dependencies/m:dependency", NS)
                + r.findall("m:profiles/m:profile/m:dependencies/m:dependency", NS))
        for el in deps:
            g, a = resolve(_text(el, "m:groupId"), props), _text(el, "m:artifactId")
            if (not g or not a or a in own_artifacts or g == own_group
                    or (_text(el, "m:scope") or "") in ("test", "import")):
                continue                                    # the build's own modules, tests, BOM imports
            v = resolve(_text(el, "m:version"), props) or managed.get((g, a))
            if not v or "${" in v or (g, a, v) in seen:
                continue
            seen.add((g, a, v))
            out.append(Component(ecosystem="maven", group=g, name=a, version=v, purl=f"pkg:maven/{g}/{a}@{v}",
                                 path=path.relative_to(repo).as_posix()))
    return out


# --------------------------------------------------------------------- edit

_DEP = re.compile(r"<dependency>(?P<body>.*?)</dependency>", re.S)
_EXCLUSIONS = re.compile(r"<exclusions>.*?</exclusions>", re.S)


def _blocked_spans(text: str) -> list[tuple[int, int]]:
    """<plugins> and <pluginManagement> sections: their dependencies are build tools."""
    return [m.span() for m in re.finditer(r"<(plugins|pluginManagement|exclusions)>.*?</\1>", text, re.S)]


def _tag(body: str, tag: str) -> Optional[re.Match]:
    return re.search(rf"<{tag}>\s*([^<]*?)\s*</{tag}>", _EXCLUSIONS.sub(lambda m: " " * len(m.group(0)), body))


def _occurrences(text: str, group: str, artifact: str) -> list[dict]:
    blocked = _blocked_spans(text)
    managed = [m.span() for m in re.finditer(r"<dependencyManagement>.*?</dependencyManagement>", text, re.S)]
    out = []
    for m in _DEP.finditer(text):
        if any(s <= m.start() < e for s, e in blocked):
            continue
        body = m.group("body")
        g, a = _tag(body, "groupId"), _tag(body, "artifactId")
        if not g or not a or g.group(1) != group or a.group(1) != artifact:
            continue
        v = _tag(body, "version")
        out.append({"start": m.start("body"), "body": body, "version": v,
                    "managed": any(s <= m.start() < e for s, e in managed)})
    return out


def _property_def(text: str, name: str) -> Optional[re.Match]:
    props = re.search(r"<properties>.*?</properties>", text, re.S)
    if not props:
        return None
    m = re.search(rf"<{re.escape(name)}>\s*([^<]*?)\s*</{re.escape(name)}>", props.group(0))
    if not m:
        return None
    return _Shifted(m, props.start())


class _Shifted:
    """A match inside a slice, with spans in the whole text."""

    def __init__(self, m: re.Match, offset: int):
        self.m, self.offset = m, offset

    def span(self, group: int = 0) -> tuple[int, int]:
        s, e = self.m.span(group)
        return s + self.offset, e + self.offset


def _replace(text: str, span: tuple[int, int], value: str) -> str:
    return text[:span[0]] + value + text[span[1]:]


def _text_props(text: str) -> dict[str, str]:
    block = re.search(r"<properties>(.*?)</properties>", text, re.S)
    return dict(re.findall(r"<([\w.-]+)>\s*([^<]*?)\s*</\1>", block.group(1))) if block else {}


def _scope_props(files: list[Path], texts: dict[Path, str]) -> dict[Path, dict[str, str]]:
    """Properties visible in each pom: the root's, overridden by its own."""
    root = _text_props(texts[files[0]]) if files else {}
    return {p: {**root, **_text_props(texts[p])} for p in files}


def _uses(files: list[Path], texts: dict[Path, str], name: str) -> tuple[set[tuple[str, str]], int]:
    """(group, artifact) of dependency blocks whose version is ${name}, and how many
    uses of ${name} are not such a version (plugin versions, other elements)."""
    users, in_deps = set(), 0
    for p in files:
        for m in _DEP.finditer(texts[p]):
            body = m.group("body")
            v, g, a = _tag(body, "version"), _tag(body, "groupId"), _tag(body, "artifactId")
            if v and v.group(1) == "${" + name + "}" and g and a:
                users.add((g.group(1), a.group(1)))
                in_deps += 1
    total = sum(texts[p].count("${" + name + "}") for p in files)
    return users, total - in_deps


def family(group: str) -> str:
    """The release train a group belongs to: its first three segments
    (com.fasterxml.jackson.core and .dataformat are one train; io.netty is its own)."""
    return ".".join(group.split(".")[:3])


def _family_property(files, texts, group: str, name: str) -> bool:
    """A version property only used as the version of dependencies of one release
    train: the family is released together and must move together."""
    users, other = _uses(files, texts, name)
    return other == 0 and bool(users) and all(family(g) == family(group) for g, _ in users)


def lockstep(repo: Path, group: str, artifact: str) -> set[tuple[str, str]]:
    """Artifacts that share this one's version property: they must move (and be vetted) together."""
    files = poms(repo)
    texts = {p: p.read_text(encoding="utf-8") for p in files}
    out = set()
    for p in files:
        for o in _occurrences(texts[p], group, artifact):
            prop = o["version"] and re.fullmatch(r"\$\{([^}]+)\}", o["version"].group(1))
            if prop and _family_property(files, texts, group, prop.group(1)):
                out |= _uses(files, texts, prop.group(1))[0]
    return out - {(group, artifact)}


def bump(repo: Path, group: str, artifact: str, version: str, current: Optional[str] = None) -> list[str]:
    """Set group:artifact (at `current`, or every version if None) to `version`; returns
    the changed files. A version property shared by one family of artifacts is changed
    as a whole: the caller vets the whole family first (see lockstep())."""
    files = poms(repo)
    texts = {p: p.read_text(encoding="utf-8") for p in files}
    props = _scope_props(files, texts)
    occs = {p: _occurrences(texts[p], group, artifact) for p in files}

    edits: dict[Path, set[tuple[int, int]]] = {}       # computed on the original text, applied last
    for path in files:
        for o in occs[path]:
            v = o["version"]
            if v is None:
                continue                                         # versionless: managed elsewhere
            if current and resolve(v.group(1), props[path]) != current:
                continue                                         # another version of it: another match
            start = o["start"] + v.start(1)
            span = (start, start + len(v.group(1)))
            prop = re.fullmatch(r"\$\{([^}]+)\}", v.group(1))
            if prop:
                name = prop.group(1)
                definer = next((p for p in [path] + files if _property_def(texts[p], name)), None)
                users, other = _uses(files, texts, name)
                only_this = other == 0 and users <= {(group, artifact)}
                if definer is not None and (only_this or _family_property(files, texts, group, name)):
                    edits.setdefault(definer, set()).add(_property_def(texts[definer], name).span(1))
                    continue
                # shared with unrelated artifacts (or defined in a parent): pin this one alone
            edits.setdefault(path, set()).add(span)

    if not edits:
        root = files[0] if files else repo / "pom.xml"
        if not root.exists():
            raise FileNotFoundError(f"no pom.xml in {repo}")
        texts[root] = _add_management(texts[root], group, artifact, version)
        edits[root] = set()

    for path, spans in edits.items():
        for span in sorted(spans, reverse=True):
            texts[path] = _replace(texts[path], span, version)
        path.write_text(texts[path], encoding="utf-8")
    return sorted(p.relative_to(repo).as_posix() for p in edits)


def _line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def _indent_at(text: str, pos: int) -> str:
    return re.match(r"[ \t]*", text[_line_start(text, pos):]).group(0)


def _entry(indent: str, step: str, group: str, artifact: str, version: str) -> str:
    inner = indent + step
    return (f"{indent}<dependency>\n{inner}<groupId>{group}</groupId>\n{inner}<artifactId>{artifact}</artifactId>\n"
            f"{inner}<version>{version}</version>\n{indent}</dependency>\n")


def _add_management(text: str, group: str, artifact: str, version: str) -> str:
    """Override the version through the root pom's <dependencyManagement>, in the file's own indentation."""
    step = (re.search(r"\n([ \t]+)<", text) or re.match(r"()", "")).group(1) or "    "
    dm = re.search(r"<dependencyManagement>\s*<dependencies>.*?(</dependencies>)", text, re.S)
    if dm:
        close = dm.start(1)
        at = _line_start(text, close)
        indent = _indent_at(text, close) + step
        return text[:at] + _entry(indent, step, group, artifact, version) + text[at:]
    anchor = re.search(r"^([ \t]*)<dependencies>", text, re.M) or re.search(r"^([ \t]*)</project>", text, re.M)
    if anchor is None:
        raise ValueError("pom.xml has no <dependencies> or </project> to anchor an override")
    base = anchor.group(1) if anchor.group(0).lstrip().startswith("<dependencies>") else anchor.group(1) + step
    block = (f"{base}<dependencyManagement>\n{base}{step}<dependencies>\n"
             + _entry(base + step * 2, step, group, artifact, version)
             + f"{base}{step}</dependencies>\n{base}</dependencyManagement>\n")
    at = anchor.start()
    return text[:at] + block + text[at:]
