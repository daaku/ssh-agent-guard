# Builds ssh-agent-guard from this checkout: makepkg here, then pacman -U the package.
importpath=github.com/daaku/ssh-agent-guard
pkgname=ssh-agent-guard
pkgver=$(git rev-list --count HEAD)
pkgrel=1
pkgdesc='ssh-agent proxy that unlocks the default Secret Service collection when the agent has no keys'
arch=('x86_64')
url="https://$importpath"
license=('MIT')
depends=(
  'glibc'   # the loader: a PIE binary is loaded by it, cgo or not
  'systemd' # busctl, and the socket activated user units
)
makedepends=('go')
optdepends=(
  'openssh: ssh-agent.socket, the default upstream agent'
  'keepassxc: a Secret Service whose unlock loads keys into the agent'
  'gnome-keyring: a Secret Service'
)

build() {
  cd ..
  export GOFLAGS='-buildmode=pie -trimpath -mod=readonly -modcacherw'
  CGO_ENABLED=0 go build -o build/ssh-agent-guard .
}

check() {
  cd ..
  CGO_ENABLED=0 go test -mod=readonly .
}

package() {
  cd ..
  install -Dm755 build/ssh-agent-guard "$pkgdir/usr/bin/ssh-agent-guard"
  # User units: the proxy serves a user's own agent, as that user.
  install -Dm644 systemd/ssh-agent-guard.socket "$pkgdir/usr/lib/systemd/user/ssh-agent-guard.socket"
  install -Dm644 systemd/ssh-agent-guard.service "$pkgdir/usr/lib/systemd/user/ssh-agent-guard.service"
  install -Dm644 readme.md "$pkgdir/usr/share/doc/ssh-agent-guard/readme.md"
  install -Dm644 license "$pkgdir/usr/share/licenses/ssh-agent-guard/license"
}
