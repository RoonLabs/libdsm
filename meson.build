project('libdsm', ['c'],
    version: '0.3.2',
    license: ['LGPL2'],
    default_options: ['c_std=c99',
                      'warning_level=2',
                      'buildtype=release',
                      'b_ndebug=if-release'],
    meson_version: '>= 0.50.0')

#Soname
dsm_soname_version = '3.1.0'
if host_machine.system() == 'windows'
  dsm_soversion = ''
else
  dsm_soversion = dsm_soname_version.split('.')[0]
endif

conf_data = configuration_data()
conf_data.set_quoted('URANDOM', '/dev/urandom') #TODO
conf_data.set('_FORTIFY_SOURCE', 2,
              description: 'Define to 2 to get glibc warnings.')
conf_data.set('_FILE_OFFSET_BITS', 64,
              description: 'Define to 64 for large file support.')
conf_data.set('_DEFAULT_SOURCE', 1)

cc = meson.get_compiler('c')

test_args = ''

# Check headers
if cc.has_header('bsd/string.h')
  conf_data.set('HAVE_BSD_STRING_H', 1)
endif

if cc.has_header('alloca.h')
  conf_data.set('HAVE_ALLOCA_H', 1)
endif

if cc.has_header('sys/queue.h')
  conf_data.set('HAVE_SYS_QUEUE_H', 1)
endif

if cc.has_header('arpa/inet.h')
  conf_data.set('HAVE_ARPA_INET_H', 1)
endif

if cc.has_header('sys/socket.h')
  conf_data.set('HAVE_SYS_SOCKET_H', 1)
endif

if cc.has_header('sys/time.h')
  conf_data.set('HAVE_SYS_TIME_H', 1)
endif

if cc.has_header('ifaddrs.h')
  conf_data.set('HAVE_IFADDRS_H', 1)
endif


# Check functions
if host_machine.system() == 'linux'
  test_args += '-D_GNU_SOURCE'
  add_project_arguments('-D_GNU_SOURCE', language: 'c')
  add_project_arguments('-D_PLATFORM_LINUX', language: 'c')
elif host_machine.system() == 'darwin'
  test_args += '-D_DARWIN_C_SOURCE'
  add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
  add_project_arguments('-D_PLATFORM_MACOSX', language: 'c')
else
  if host_machine.system() == 'windows'
    add_project_arguments('-D_PLATFORM_WINDOWS', language: 'c')
  elif host_machine.system() == 'cygwin'
    add_project_arguments('-D_PLATFORM_WINDOWS', language: 'c')
  endif
  
  test_args += '-D_POSIX_C_SOURCE=200809L'
  add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')
endif

compat_sources = []

if cc.has_function('strlcpy', prefix: '#include <string.h>', args: test_args)
  conf_data.set('HAVE_STRLCPY', 1)
else
  compat_sources += 'compat/strlcpy.c'
endif

if cc.has_function('strndup', prefix: '#include <string.h>', args: test_args)
  conf_data.set('HAVE_STRNDUP', 1)
else
  compat_sources += 'compat/strndup.c'
endif

#this seems to work, and the tests for it were not working in our build
#environment
conf_data.set('HAVE_CLOCK_GETTIME', 1)

if cc.has_function('pipe')
  conf_data.set('HAVE_PIPE', 1)
endif

if cc.has_function('_pipe')
  conf_data.set('HAVE__PIPE', 1)
endif

if cc.has_function('getifaddrs')
  conf_data.set('HAVE_GETIFADDRS', 1)
endif

if cc.has_function('nl_langinfo')
  conf_data.set('HAVE_NL_LANGINFO', 1)
endif

# Check for struct timespec
if cc.has_type('struct timespec', prefix: '#include <time.h>')
  conf_data.set('HAVE_STRUCT_TIMESPEC', 1)
endif

if cc.has_type('clockid_t', prefix: '#include<time.h>\n#include<pthread.h>')
  conf_data.set('HAVE_CLOCKID_T', 1)
endif

deps = []
dep_thread = dependency('threads')
deps += dep_thread

config_header = configure_file(
  input: 'config.h.meson',
  output: 'config.h',
  configuration: conf_data)

libdsm_sources = [
  'contrib/mdx/md4.c',
  'contrib/mdx/md5.c',
  'contrib/rc4/rc4.c',
  'src/hmac_md5.c',
  'src/netbios_ns.c',
  'src/netbios_query.c',
  'src/netbios_session.c',
  'src/netbios_utils.c'
 ]
libdsm_sources += compat_sources

libdsm_headers = [
  'include/bdsm/netbios_defs.h',
  'include/bdsm/netbios_ns.h',
  'include/bdsm.h'
]

install_headers(libdsm_headers, subdir: 'bdsm')

includes = include_directories('.', 'contrib', 'include', 'compat')

add_project_arguments('-DHAVE_CONFIG_H=1', language: ['c'])

# Platform specific logger library

# Android use syslog
if host_machine.system() == 'android'
  deps += [cc.find_library('log', required: true)]
endif

if host_machine.system() != 'windows' and host_machine.system() != 'cygwin'
  warning_arguments = [
    '-Wall',
    '-Wsign-compare',
    '-Wextra',
    '-Wstrict-aliasing',
    '-Wstrict-overflow' ]
  
  add_project_arguments(warning_arguments, language: 'c')
  
  have_iconv = cc.has_function('iconv_open', prefix: '#include <iconv.h>')
  if not have_iconv
    dep_iconv  = [cc.find_library('iconv', required: false)]
    have_iconv = cc.has_function('iconv_open',
                                 prefix: '#include <iconv.h>',
                                 dependencies: dep_iconv)
    deps += dep_iconv
  endif

  if not have_iconv
    error('iconv is not available')
  endif
  
  dep_tasn1 = dependency('libtasn1')
  deps += dep_tasn1
  
  asn1parser_prog = find_program('asn1Parser')
  spnego_asn1_target = custom_target('spnego_asn1.c',
                                     input: 'contrib/spnego/spnego.asn1',
                                     output: 'spnego_asn1.c',
                                     command: [asn1parser_prog, '-o', '@OUTPUT@', '-n', 'spnego_asn1_conf',
                                               '@INPUT@'])
  libdsm_sources += [
    'contrib/mdx/md4.c',
    'contrib/mdx/md5.c',
    'contrib/rc4/rc4.c',
    spnego_asn1_target,
    'src/hmac_md5.c',
    'src/smb_buffer.c',
    'src/smb_dir.c',
    'src/smb_fd.c',
    'src/smb_file.c',
    'src/smb_spnego.c',
    'src/smb_message.c',
    'src/smb_ntlm.c',
    'src/smb_session.c',
    'src/smb_session_msg.c',
    'src/smb_share.c',
    'src/smb_stat.c',
    'src/smb_trans2.c',
    'src/smb_transport.c',
    'src/smb_utils.c' ]

  libdsm_headers += [
    'include/bdsm/smb_defs.h',
    'include/bdsm/smb_dir.h',
    'include/bdsm/smb_file.h',
    'include/bdsm/smb_session.h',
    'include/bdsm/smb_share.h',
    'include/bdsm/smb_stat.h',
    'include/bdsm/smb_types.h',
    'include/bdsm.h'
  ]
endif

libdsm = library('dsm',
                 libdsm_sources,
                 version: dsm_soname_version,
                 soversion: dsm_soversion,
                 include_directories: includes,
                 dependencies: deps,
                 install: true)

watcherobj = executable('watcher', 'src/roon_watcher.c',
                        link_with : libdsm,
                        include_directories: includes)

