subinclude("//:version")

architectures = [
    "darwin_amd64",
    "darwin_arm64",
    "freebsd_amd64",
    "linux_amd64",
    "linux_arm64",
]

go_toolchain(
    name = "release_toolchain",
    version= "1.20",
    architectures = architectures,
)

def cross_compile(version, arch):
    return build_rule(
        name = f"puku_{arch}",
        srcs = [f"///{arch}//:puku"],
        outs = [f"puku-{version}-{arch}"],
        cmd = "mv $SRC $OUT",
        labels = ["manual"],
    )

filegroup(
    name = f"release_files",
    srcs = [cross_compile(VERSION, arch) for arch in architectures],
    labels = [
        f"hlink:plz-out/package",
        "manual",
    ],
)