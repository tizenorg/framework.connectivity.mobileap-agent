Name:       mobileap-agent
Summary:    Mobile AP daemon for setting tethering environments
Version:    0.1.89
Release:    1
Group:      TO_BE/FILLED_IN
License:    Flora License
Source0:    %{name}-%{version}.tar.gz
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(gthread-2.0)
BuildRequires: pkgconfig(pmapi)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(notification)
BuildRequires: pkgconfig(libssl)
BuildRequires: pkgconfig(secure-storage)
BuildRequires: pkgconfig(capi-network-connection)
BuildRequires: pkgconfig(capi-network-bluetooth)
BuildRequires: cmake
Requires(post): /usr/bin/vconftool
Requires: iptables
Requires: dnsmasq
%description
Mobile AP daemon for setting tethering environments

%prep
%setup -q

%build
%cmake .
make %{?jobs:-j%jobs}

%install
%make_install

%post
/usr/bin/vconftool set -t int memory/mobile_hotspot/connected_device "0" -u 0 -i -f
/usr/bin/vconftool set -t int memory/mobile_hotspot/mode "0" -u 0 -i -f
/usr/bin/vconftool set -t int db/mobile_hotspot/security "0" -u 0 -f
/usr/bin/vconftool set -t int db/mobile_hotspot/hide "0" -u 0 -f

%files
%manifest mobileap-agent.manifest
%defattr(-,root,root,-)
/usr/share/dbus-1/services/org.tizen.tethering.service
%{_bindir}/mobileap-agent

%changelog
* Tue Apr 09 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.1.86-1
- Fix the multiple notification issue
- Support i80211n
- Channel is changed to 6
- Implement status notification for bluetooth visibility
- Change the power manager api
- Implement connection timer
- Reference count is used
- Support Mobile AP

* Sat Feb 16 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.1.85-2
- Function return value is checked
- Private SSID is considered
- Build option clean-up and g_type_init is deprecated from glib 2.35

* Thu Feb 14 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.1.84-1
- User is specified in service file for Dbus auto activation

* Mon Jan 28 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.1.83-1
- Remove unrequired log

* Thu Jan 24 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.1.82-1
- Indications for Wi-Fi tethering setting change are added
- DNS Forward and Use of Tethering cellular profile are removed
- Dbus service / interface / object names are changed

* Mon Jan 14 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.1.81-1
- dhcp lease delete is handled based on IP Address
- DNS Forward by netfilter is implemented
- Vconf key for flight mode is changed

* Fri Dec 07 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.80-1
- Notification API's usage is changed
- Duplicated station information issue is fixed
- Improper notification type is used
- Timeout(Auto disconnection) feature is implemented
- Notification for timeout event is implemented

* Thu Nov 08 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.79-1
- Notification's API usage is changed

* Tue Nov 06 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.78-1
- Unnecessary BT API is removed

* Sat Nov 03 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.77-1
- Prevent issues are fixed

* Tue Oct 30 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.76-1
- Vconf enum is changed (SETTING_USB_MOBILE_HOTSPOT -> SETTING_USB_TETHERING_MODE)
- Private code is separated

* Mon Oct 29 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.75-1
- Code clean-up and path for notification icon is changed

* Thu Oct 22 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.74-1
- License is added

* Thu Oct 11 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.73-1
- Source package name is changed (libmobileap -> mobileap-agent)

* Thu Oct 11 2012 Injun Yang <injun.yang@samsung.com> 0.1.72-1
- Launch kcp-agent

* Fri Sep 28 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.71-1
- Fix memory corruption

* Fri Sep 21 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.70-1
- Manifest file is added for SMACK

* Wed Sep 19 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.69-1
- The code for Legacy APIs is removed

* Wed Sep 14 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.68-1
- Bluetooth PAN Managed APIs are applied
- MDM Phase 2 implementation

* Wed Sep 06 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.67-1
- Connection Managed APIs are applied
- Network status is not checked in agent

* Wed Aug 01 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.66-1
- Wi-Fi tethering setting values are managed here
- Deprecated APIs from glib-2.3.0 are replaced
- Notification Icon is changed

* Fri Jul 13 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.65-1
- Wi-Fi tethering disable / enable issues are fixed

* Fri Jul 06 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.64-1
- Unnecessary dependency is removed

* Mon Jun 25 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.63-1
- Data usage is fixed

* Thu May 31 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.62-1
- Wi-Fi tethering security is implemented
- API for getting USB interface information is implemented

* Wed May 23 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.61-1
- Tethering app. dependency is added

* Tue May 22 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.60-1
- Wi-Fi interface name is changed from eth0 to wlan0

* Tue May 22 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.59-1
- Below changes are applied
- Ignore mdm failure case
- CAPI bugs are fixed
- Bug of _remove_station_info_all() is fixed
- Launch tethering applicatoin from notification

* Tue May 08 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.58-1
- Hostapd control interface is implemented

* Mon Apr 09 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.57-1
- Unused vconfkey is removed

* Wed Mar 14 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.56-1
- Export API's are changed

* Mon Feb 06 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.55-2
- Fix build error

* Mon Feb 06 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.1.55-1
- Test code is modified
- Code clean-up
- Notification is implemented
- MDM bug fix
