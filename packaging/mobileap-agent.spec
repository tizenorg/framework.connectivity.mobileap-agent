Name:		mobileap-agent
Summary:	Mobile AP daemon for setting tethering environments
Version:	1.0.17
Release:	1
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(dbus-glib-1)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(gthread-2.0)
BuildRequires:	pkgconfig(deviced)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(notification)
BuildRequires:	pkgconfig(capi-network-connection)
BuildRequires:	pkgconfig(capi-network-bluetooth)
BuildRequires:	pkgconfig(syspopup-caller)
BuildRequires:	pkgconfig(bundle)
BuildRequires:	pkgconfig(appcore-common)
BuildRequires:	pkgconfig(capi-network-wifi-direct)
BuildRequires:	pkgconfig(capi-network-wifi)
BuildRequires:	pkgconfig(alarm-service)
BuildRequires:	pkgconfig(appsvc)
BuildRequires:	pkgconfig(libssl)
BuildRequires:	cmake
Requires(post):	/usr/bin/vconftool
Requires(post):	bluetooth-agent
Requires(post):	ss-server
Requires:	iproute2
Requires:	iptables
Requires:	dnsmasq

%description
Mobile AP daemon for setting tethering environments

%prep
%setup -q


%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%cmake -DCMAKE_BUILD_TYPE="" \
	.

make %{?jobs:-j%jobs}


%install
%make_install

%post
/usr/bin/vconftool set -t string memory/private/mobileap-agent/ssid "" -u 0 -i -f -s system::vconf_network
/usr/bin/vconftool set -t int memory/mobile_hotspot/connected_device "0" -u 0 -i -f -s system::vconf_network
/usr/bin/vconftool set -t int memory/mobile_hotspot/mode "0" -u 0 -i -f -s system::vconf_network
/usr/bin/vconftool set -t int db/mobile_hotspot/security "1" -u 5000 -f -s system::vconf_network
/usr/bin/vconftool set -t int db/mobile_hotspot/hide "0" -u 5000 -f -s system::vconf_network

/bin/chmod +x /opt/etc/dump.d/module.d/tethering_dump.sh

%files
%manifest mobileap-agent.manifest
%defattr(-,root,root,-)
/usr/share/dbus-1/services/org.tizen.tethering.service
%{_bindir}/mobileap-agent
/opt/etc/dump.d/module.d/tethering_dump.sh

