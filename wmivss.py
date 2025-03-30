#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   A similar approach to smbexec but executing commands through WMI.
#   Main advantage here is it runs under the user (has to be Admin)
#   account, not SYSTEM, plus, it doesn't generate noisy messages
#   in the event log that smbexec.py does when creating a service.
#   Drawback is it needs DCOM, hence, I have to be able to access
#   DCOM ports at the target machine.
#
# Author:
#   beto (@agsolino)
#
# Reference for:
#   DCOM
#

from __future__ import division
from __future__ import print_function
import sys
import argparse
import logging
from datetime import datetime, timedelta

from impacket.dcerpc.v5.dcom.wmi import WBEM_INFINITE, DCERPCSessionError
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5.keytab import Keytab


class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False,
                 kdcHost=None):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def list_shadowcopies(self, addr):
        """ Liste les shadow copies disponibles """
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32ShadowInstances = iWbemServices.CreateInstanceEnum('Win32_ShadowCopy')
            all_instances = list()

            while True:
                try:
                    instances = win32ShadowInstances.Next(WBEM_INFINITE, 1)
                    all_instances.extend(instances)
                except DCERPCSessionError as e:
                    break

            
            if len(all_instances) is 0 :
                print("No shadow copie")
            else:
                print("Available shadow copies: ")
                for i in all_instances:
                    print(i.ID, " ", i.VolumeName, end=": ")
                    if i.ClientAccessible == "True":
                        year = int(i.InstallDate[:4])
                        month = int(i.InstallDate[4:6])
                        day = int(i.InstallDate[6:8])
                        hour = int(i.InstallDate[8:10])
                        minute = int(i.InstallDate[10:12])
                        second = int(i.InstallDate[12:14])
                        second_frac = float(i.InstallDate[14:21])
                        timezone = int(i.InstallDate[21:25])
                        assert timezone % 60 == 0
                        d = datetime(year, month, day, hour, minute, second)
                        d -= timedelta(minutes=timezone)
                        probableDriveLetter =  "C"
                        share_tag = "\\\\" + addr + "\\" + probableDriveLetter + "$\\@" + d.strftime("GMT-%Y.%m.%d-%H.%M.%S")
                        print(share_tag)
                    else:
                        print()        

        except Exception as e:
            logging.error(str(e))
        finally:
            dcom.disconnect()

    def create_shadowcopy(self, addr, driveLetter):
        """ Crée une shadow copy sur le lecteur spécifié """
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32Shadow, _ = iWbemServices.GetObject('Win32_ShadowCopy')
            res = win32Shadow.Create(f"{driveLetter}:\\", "ClientAccessible")
            print(f"Shadowcopy created with ID: {res.ShadowID}")
        except Exception as e:
            logging.error(str(e))
        finally:
            dcom.disconnect()

if __name__ == "__main__":
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell using Windows "
                                                                "Management Instrumentation.")
    parser.add_argument("mode", choices=["list", "create"], help="Mode: list or create a shadow copy")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-drive-letter', action='store', help='Driver letter to take the VSS from (default C:\\)')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION",
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on '
                            'target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) '
                                                                            'specified in the target parameter')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

   
    domain, username, password, address = parse_target(options.target)

    try:
        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = WMIEXEC('', username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)

        if options.mode == "list":
            executer.list_shadowcopies(options.target)
        elif options.mode == "create":
            if not options.drive_letter:
                print("Drive letter is required for shadow copy creation.")
            else:
                executer.create_shadowcopy(options.target, options.drive_letter.upper())

        # executer.run(address, drive_letter)
    except KeyboardInterrupt as e:
        logging.error(str(e))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)

    sys.exit(0)
