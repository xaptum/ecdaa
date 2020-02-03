# Packaging for Debian.

## Background
Read http://honk.sigxcpu.org/projects/git-buildpackage/manual-html/ to
learn about git-package.

We use the "No upstream tarballs" flow describe here:
http://honk.sigxcpu.org/projects/git-buildpackage/manual-html/gbp.import.upstream-git.html#gbp.import.upstream.git.notarball

## Prerequisites

Your Debian build environment will need to have `build-essential`,
`cmake`, `debhelper`, and `git-buildpackage` installed.

## Branches

Branch `debian/<name>` is the master branch for the `debian/*`
directory for the `<name`> version of Debian. For example, the branch
`debian/jessie` is used to build packages for Debian 8.

The `git-buildpackage` toolchain is used to manage these branches and
build new debs.

## Import a New Version

Check out the appropriate `debian/<name>` branch:

    git checkout debian/jessie

Import the latest release tag.

    git merge v0.5.0
    
Note that this merge is largely cosmetic.  The package will be built
against the latest tag in the local repo, not the code currently on
the `debian/jessie` branch.  Merging the tag into the debian branch is
just a convenience for developers looking at the git history.

## Update the Change Log

Use `gbp dch` to generate the changelog.

    gbp dch --release --auto debian/

Manually modify the changelog as needed.

    emacs debian/changelog
    
Commit the modified changelog.

    git commit -m "release 0.5.0-1" debian/changelog
    
## Build the Debs

Use `gbp buildpackage` to create the packages.

    gbp buildpackage -uc -us --git-tag
    
The `-uc -us` options disable GPG signing.
