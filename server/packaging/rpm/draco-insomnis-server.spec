Name:           draco-insomnis-server
Version:        %{draco_version}
Release:        1
Summary:        Firewall in front of every PHP site on the server
License:        GPL-2.0-or-later
URL:            https://github.com/fermatacordis-create/draco-insomnis
Source0:        draco-insomnis-server-%{version}.tar.gz
BuildArch:      noarch
Packager:       Draco Insomnis <draco@opnv.systems>
Requires:       php-cli >= 8.0
Requires:       php-pdo
Recommends:     php-pecl-apcu

%description
Draco Insomnis Server loads before every PHP script (auto_prepend_file) and
gives any PHP application the Draco Insomnis firewall: SQL injection, file
inclusion and scanner rules, a block list with ranges, a country filter, an
anti-copy pace limit, security headers and a review request on the block
page. Off until "draco enable"; the firewall starts in "log".

%prep
%setup -q

%build

%install
mkdir -p %{buildroot}/usr/share/draco-insomnis %{buildroot}/usr/bin %{buildroot}/etc/draco-insomnis %{buildroot}/usr/lib/systemd/system %{buildroot}/var/lib/draco-insomnis
cp -R share/. %{buildroot}/usr/share/draco-insomnis/
chmod 755 %{buildroot}/usr/share/draco-insomnis/bin/draco
ln -s /usr/share/draco-insomnis/bin/draco %{buildroot}/usr/bin/draco
install -m 644 draco.ini %{buildroot}/etc/draco-insomnis/draco.ini
install -m 644 systemd/draco-insomnis-cleanup.service systemd/draco-insomnis-cleanup.timer %{buildroot}/usr/lib/systemd/system/

%files
%license share/LICENSE
%doc README.md
/usr/share/draco-insomnis
/usr/bin/draco
%dir /etc/draco-insomnis
%config(noreplace) /etc/draco-insomnis/draco.ini
/usr/lib/systemd/system/draco-insomnis-cleanup.service
/usr/lib/systemd/system/draco-insomnis-cleanup.timer
%dir %attr(1733, root, root) /var/lib/draco-insomnis

%post
# SELinux: PHP-FPM and Apache (httpd_t) may write their evidence folders, and nothing else there.
if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -a -t httpd_sys_rw_content_t '/var/lib/draco-insomnis(/.*)?' 2>/dev/null || \
    semanage fcontext -m -t httpd_sys_rw_content_t '/var/lib/draco-insomnis(/.*)?' 2>/dev/null || :
  restorecon -R /var/lib/draco-insomnis 2>/dev/null || :
elif command -v chcon >/dev/null 2>&1 && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
  chcon -R -t httpd_sys_rw_content_t /var/lib/draco-insomnis 2>/dev/null || :
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || :
  systemctl enable --now draco-insomnis-cleanup.timer >/dev/null 2>&1 || :
fi
if [ "$1" -eq 1 ]; then
  echo "Draco Insomnis Server is installed but not loaded yet. Turn it on with:  sudo draco enable"
fi

%preun
if [ "$1" -eq 0 ]; then
  # PHP must stop loading the guard before its files go away.
  /usr/bin/draco disable >/dev/null 2>&1 || :
  if [ -d /run/systemd/system ]; then
    systemctl disable --now draco-insomnis-cleanup.timer >/dev/null 2>&1 || :
  fi
fi

%postun
if [ "$1" -eq 0 ] && command -v semanage >/dev/null 2>&1; then
  semanage fcontext -d '/var/lib/draco-insomnis(/.*)?' 2>/dev/null || :
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || :
fi
