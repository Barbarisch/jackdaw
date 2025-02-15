#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from json import detect_encoding
import os
import sys
import logging
import asyncio
import platform
import datetime

from sqlalchemy import exc  # for pyinstaller
from sqlalchemy.sql import default_comparator  # for pyinstaller
from sqlalchemy.ext import baked  # for pyinstaller

from aiosmb import logger as smblogger
from aiosmb._version import __version__ as smbversion
from msldap import logger as msldaplogger
from msldap._version import __version__ as ldapversion
from asysocks import logger as asysockslogger

from jackdaw.dbmodel import create_db, get_session
from jackdaw.gatherer.gatherer import Gatherer

from jackdaw._version import __banner__
from jackdaw._version import __version__ as jdversion
from jackdaw import logger as jdlogger
from jackdaw.utils.argshelper import construct_ldapdef, construct_smbdef
from jackdaw.credentials.credentials import JackDawCredentials
from jackdaw.gatherer.smb.smbfile import SMBFileGatherer
from msldap.commons.url import MSLDAPURLDecoder

import multiprocessing


async def run_auto(ldap_worker_cnt=None, smb_worker_cnt=500, dns=None, work_dir='./workdir', db_conn=None, show_progress=True, no_work_dir=False):
	try:
		if platform.system() != 'Windows':
			raise Exception('auto mode only works on windows!')
		
		smblogger.setLevel(100)
		from winacl.functions.highlevel import get_logon_info
		logon = get_logon_info()
		
		jdlogger.debug(str(logon))
		if logon['domain'] == '' or logon['logonserver'] == '':
			if logon['domain'] == '':
				logon['domain'] = os.environ['USERDOMAIN']
			if logon['logonserver'] == '':
				logon['logonserver'] = os.environ['LOGONSERVER'].replace('\\', '')

			if logon['domain'] == '' or logon['logonserver'] == '':
				return False, Exception("Failed to find user's settings! Is this a domain user?")
		
		try:
			# checking connection can be made over ldap...
			reader, writer = await asyncio.wait_for(asyncio.open_connection(logon['logonserver'], 389), 2)
			writer.close()
		except:
			return False, Exception("Failed to connect to server %s over LDAP" % (logon['logonserver']))

		if db_conn is None:
			db_loc = '%s_%s.db' % (logon['domain'], datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
			db_conn = 'sqlite:///%s' % db_loc
			create_db(db_conn)
		ldap_url = 'ldap+sspi-ntlm://%s\\%s:jackdaw@%s' % (logon['domain'], logon['username'], logon['logonserver'])
		# smb_url = 'smb2+sspi-kerberos://%s\\%s:jackdaw@%s' % (logon['domain'], logon['username'], logon['logonserver'])
		smb_url = 'smb2+sspi-ntlm://%s\\%s:jackdaw@%s' % (logon['domain'], logon['username'], logon['logonserver'])

		jdlogger.debug('LDAP connection: %s' % ldap_url)
		jdlogger.debug('SMB  connection: %s' % smb_url)
		if dns is None:
			from jackdaw.gatherer.rdns.dnstest import get_correct_dns_win
			srv_domain = '%s.%s' % (logon['logonserver'], logon['dnsdomainname'])
			dns = await get_correct_dns_win(srv_domain)
			if dns is None:
				jdlogger.debug('Failed to identify DNS server!')
			else:
				dns = str(dns)
				jdlogger.debug('DNS server selected: %s' % str(dns))

		kerb_url = 'auto'
		with multiprocessing.Pool() as mp_pool:
			gatherer = Gatherer(
				db_conn, 
				work_dir, 
				ldap_url, 
				smb_url,
				kerb_url=kerb_url,
				ldap_worker_cnt=ldap_worker_cnt, 
				smb_worker_cnt=smb_worker_cnt, 
				mp_pool=mp_pool, 
				smb_gather_types=['all'], 
				progress_queue=None, 
				show_progress=show_progress,
				calc_edges=True,
				dns=dns,
				no_work_dir=no_work_dir
			)
			res, err = await gatherer.run()
			if err is not None:
				raise err
			return True, None
	except Exception as e:
		return False, e


async def run(args):
	try:
		if args.silent is True:
			print(__banner__)
		if args.verbose == 0:
			logging.basicConfig(level=logging.INFO)
			jdlogger.setLevel(logging.INFO)
			msldaplogger.setLevel(logging.CRITICAL)
			asysockslogger.setLevel(logging.CRITICAL)
			smblogger.setLevel(100)
			
		elif args.verbose == 1:
			logging.basicConfig(level=logging.DEBUG)
			jdlogger.setLevel(logging.DEBUG)
			msldaplogger.setLevel(logging.WARNING)
			smblogger.setLevel(logging.CRITICAL)
			asysockslogger.setLevel(logging.CRITICAL)
			
		elif args.verbose > 1:
			logging.basicConfig(level=1)
			msldaplogger.setLevel(logging.DEBUG)
			jdlogger.setLevel(1)
			smblogger.setLevel(1)
			asysockslogger.setLevel(1)

		if not args.sql and args.command != 'auto':
			print('SQL connection identification is missing! You need to provide the --sql parameter')
			sys.exit()
		
		work_dir = args.work_dir
		ldap_url = None
		smb_url = None

		if hasattr(args, 'ldap_url'):
			ldap_url = args.ldap_url
		if hasattr(args, 'smb_url'):
			smb_url = args.smb_url

		db_conn = args.sql
		db_session = None
		if db_conn is not None:
			db_session = get_session(db_conn)
			os.environ['JACKDAW_SQLITE'] = '0'
			if args.sql.lower().startswith('sqlite'):
				os.environ['JACKDAW_SQLITE'] = '1'
		else:
			os.environ['JACKDAW_SQLITE'] = '1'
		
		if args.command == 'enum':
			with multiprocessing.Pool() as mp_pool:
				gatherer = Gatherer(
					db_session, 
					work_dir, 
					ldap_url, 
					smb_url,
					kerb_url=args.kerberoast,
					ldap_worker_cnt=args.ldap_workers, 
					smb_worker_cnt=args.smb_workers, 
					mp_pool=mp_pool, 
					smb_gather_types=['all'], 
					progress_queue=None, 
					show_progress=args.silent,
					calc_edges=True,
					ad_id=None,
					dns=args.dns,
					no_work_dir=args.no_work_dir,
					proxy=args.proxy,
					keep_sd_file=True,
				)
				res, err = await gatherer.run()
				if err is not None:
					raise err

		elif args.command == 'auto':
			_, err = await run_auto(
				ldap_worker_cnt=args.ldap_workers,
				smb_worker_cnt=args.smb_workers,
				dns=args.dns,
				work_dir=work_dir,
				show_progress=args.silent,
				no_work_dir=args.no_work_dir
			)
			if err is not None:
				print(err)

		elif args.command == 'dbinit':
			create_db(db_conn)
		
		elif args.command == 'adinfo':
			from jackdaw.dbmodel.adinfo import ADInfo
			from jackdaw.utils.table import print_table
			
			rows = [['Ad ID', 'domain name', 'scantime']]
			for did, distinguishedName, creation in db_session.query(ADInfo).with_entities(ADInfo.id, ADInfo.distinguishedName, ADInfo.fetched_at).all():
				name = distinguishedName.replace('DC=', '')
				name = name.replace(',', '.')
				rows.append([str(did), name, creation.isoformat()])
			print_table(rows)
			
		elif args.command == 'ldap':
			with multiprocessing.Pool() as mp_pool:
				gatherer = Gatherer(
					db_session, 
					work_dir, 
					ldap_url, 
					smb_url, 
					ldap_worker_cnt=args.ldap_workers, 
					smb_worker_cnt=None, 
					mp_pool=mp_pool, 
					smb_gather_types=['all'], 
					progress_queue=None, 
					show_progress=args.silent,
					calc_edges=args.calculate_edges,
					ad_id=args.ad_id,
					no_work_dir=args.no_work_dir,
					proxy=args.proxy
				)
				_, err = await gatherer.run()
				if err is not None:
					raise err

		elif args.command == 'kerberoast':
			gatherer = Gatherer(
				db_session,
				work_dir,
				None,
				None,
				kerb_url=args.kerberos_url,
				ldap_worker_cnt=None,
				smb_worker_cnt=None,
				mp_pool=None,
				smb_gather_types=[],
				progress_queue=None,
				show_progress=False,
				calc_edges=False,
				ad_id=args.ad_id,
				proxy=args.proxy
			)
			_, err = await gatherer.run()
			if err is not None:
				raise err
			print('Kerberoast Finished!')

		elif args.command in ['shares', 'sessions', 'localgroups', 'smball']:
			if args.command == 'smball':
				args.command = 'all'

			gatherer = Gatherer(
				db_session, 
				work_dir, 
				ldap_url, 
				smb_url,
				ad_id=args.ad_id,
				ldap_worker_cnt=None, 
				smb_worker_cnt=args.smb_workers, 
				mp_pool=None, 
				smb_gather_types=args.command, 
				progress_queue=None, 
				show_progress=args.silent,
				calc_edges=False,
				proxy=args.proxy
			)
			_, err = await gatherer.run()
			if err is not None:
				raise err

		elif args.command == 'dns':
			gatherer = Gatherer(
				db_session, 
				work_dir, 
				None, 
				None,
				ad_id=args.ad_id,
				ldap_worker_cnt=None, 
				smb_worker_cnt=None, 
				mp_pool=None, 
				smb_gather_types=None, 
				progress_queue=None, 
				show_progress=args.silent,
				calc_edges=False,
				dns=args.dns,
				proxy=args.proxy
			)
			_, err = await gatherer.run()
			if err is not None:
				raise err

		elif args.command == 'version':
			print('Jackdaw version: %s' % jdversion)
			print('MSLDAP version : %s' % ldapversion)
			print('AIOSMB version : %s' % smbversion)

		elif args.command == 'smbfiles':
			gatherer = SMBFileGatherer(
				db_session, 
				args.ad_id, 
				args.smb_url, 
				worker_cnt=args.smb_workers,
				progress_queue=None,
				show_progress=True,
				stream_data=False,
				depth=args.depth,
				to_file=args.out_file,
			)
			_, err = await gatherer.run()
			if err is not None:
				raise err
			
		elif args.command == 'creds':
			creds = JackDawCredentials(db_conn, args.domain_id)
			creds.add_credentials_impacket(args.impacket_file)

		elif args.command == 'passwords':
			creds = JackDawCredentials(db_conn)
			creds.add_cracked_passwords(args.potfile, args.disable_usercheck, args.disable_passwordcheck)
			
		elif args.command == 'uncracked':
			creds = JackDawCredentials(db_conn, args.domain_id)
			creds.get_uncracked_hashes(args.hash_type, args.history)
			
		elif args.command == 'cracked':
			creds = JackDawCredentials(db_conn, args.domain_id)
			creds.get_cracked_info()

		elif args.command == 'recalc':
			with multiprocessing.Pool() as mp_pool:
				gatherer = Gatherer(
					db_session, 
					work_dir, 
					None, 
					None, 
					mp_pool=mp_pool, 
					progress_queue=None, 
					show_progress=args.silent,
					calc_edges=True,
					store_to_db=True,
					ad_id=None,
					graph_id=args.graphid
				)
				_, err = await gatherer.run()
				if err is not None:
					raise err

		elif args.command == 'nest':
			from jackdaw.nest.wrapper import NestServer

			debug = bool(args.verbose)

			server = NestServer(
				args.sql, 
				bind_ip=args.ip,
				bind_port=args.port,
				debug=debug,
				work_dir=args.work_dir,
				graph_backend=args.backend,
			)
			server.run()
		
		elif args.command == 'ws':
			from jackdaw.nest.ws.server import NestWebSocketServer
			server = NestWebSocketServer(args.listen_ip, args.listen_port, args.sql, args.work_dir, args.backend, ssl_ctx=None, wsnet_router=args.wsrouter)
			await server.run()
		
		elif args.command == 'bhimport':
			from jackdaw.utils.bhimport import BHImport
			print('DISCLAIMER! This feature is still beta! Bloodhound acquires way less data than Jackdaw therefore not all functionality will work after import. Any errors during import will be silently ignored, use "-vvv" verbosity level to see all errors.')
			bh = BHImport.from_zipfile(args.bhfile)
			bh.db_conn = db_conn
			if args.verbose > 1:
				bh.set_debug(True)
			bh.run()
			print('Import complete!')

		elif args.command == 'bhimport2':
			from jackdaw.utils.bhimport2 import BHImport2
			print("""DISCLAIMER! This feature is still beta! Bloodhound acquires way less data than Jackdaw therefore 
			not all functionality will work after import. Any errors during import will be silently ignored, 
			use "-vvv" verbosity level to see all errors.""")
			bh = BHImport2()
			bh.db_conn = db_conn
			if args.zip:
				bh.from_zipfile(args.zip)
			bh.run()
			print('Import complete!')
		
		elif args.command == 'createcache':
			print(args)
			from jackdaw.nest.functions.graph import create as creategraphcache
			if args.backend.upper() == 'networkx'.upper():
				from jackdaw.nest.graph.backends.networkx.domaingraph import JackDawDomainGraphNetworkx
				graph_type = JackDawDomainGraphNetworkx
			elif args.backend.upper() == 'igraph'.upper():
				from jackdaw.nest.graph.backends.igraph.domaingraph import JackDawDomainGraphIGraph
				graph_type = JackDawDomainGraphIGraph
			elif args.backend.upper() == 'graphtools'.upper():
				from jackdaw.nest.graph.backends.graphtools.domaingraph import JackDawDomainGraphGrapthTools
				graph_type = JackDawDomainGraphGrapthTools

			session = get_session(db_conn)
			creategraphcache(args.graph_id, session, args.work_dir, graph_type, db_conn)

	except Exception as e:
		jdlogger.exception('main')


def main():
	if platform.system().upper() == 'WINDOWS' and len(sys.argv) == 1:
		# auto start on double click with default settings
		_, err = asyncio.run(run_auto())
		if err is not None:
			print(err)
		return

	if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
		asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

	import argparse
	
	parser = argparse.ArgumentParser(description='Gather gather gather')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, can be stacked')
	parser.add_argument('-s', '--silent', action='store_false', help='Silent mode')
	parser.add_argument('--sql', help='SQL connection string. When using SQLITE it works best with FULL FILE PATH!!!')
	parser.add_argument('--work-dir', default='./workdir', help='Working directory for caching and tempfiles')

	subparsers = parser.add_subparsers(help='commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	nest_group = subparsers.add_parser('nest', formatter_class=argparse.RawDescriptionHelpFormatter, help='Start the Nest server')
	nest_group.add_argument('--ip',  default='127.0.0.1', help='IP address to listen on')
	nest_group.add_argument('--port',  type=int, default=5000, help='IP address to listen on')
	nest_group.add_argument('--backend', default='igraph', choices=['igraph', 'networkx'], help='graph backend')

	adinfo_group = subparsers.add_parser('adinfo', help='Get a list of AD info entries')
	dbinit_group = subparsers.add_parser('dbinit', help='Creates database')
	version_group = subparsers.add_parser('version', help='version info')

	ldap_group = subparsers.add_parser('ldap', formatter_class=argparse.RawDescriptionHelpFormatter, help='Enumerate potentially vulnerable users via LDAP', epilog=MSLDAPURLDecoder.help_epilog)
	ldap_group.add_argument('ldap_url',  help='Connection specitication in URL format')
	ldap_group.add_argument('--ldap-workers', type=int, default=4, help='LDAP worker count for parallelization')
	ldap_group.add_argument('--ldap-queue-size', type=int, default=4, help='LDAP worker queue max size.')
	ldap_group.add_argument('-d', '--ad-id', help='AD id from DB. signals resumption task')
	ldap_group.add_argument('-c', '--calculate-edges', action='store_true', help='Calculate edges after enumeration')
	ldap_group.add_argument('--no-work-dir', action='store_true', help='Skip creating subdirs for temp files')
	ldap_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')
	
	auto_group = subparsers.add_parser('auto', help='auto mode, windows only!')
	auto_group.add_argument('--ldap-workers', type=int, default=4, help='LDAP worker count for parallelization')
	auto_group.add_argument('--smb-workers', type=int, default=50, help='SMB worker count for parallelization')
	auto_group.add_argument('-d', '--dns', help='DNS server for resolving IPs')
	auto_group.add_argument('--no-work-dir', action='store_true', help='Skip creating subdirs for temp files')

	recalc_group = subparsers.add_parser('recalc', help='Recalculate edges from SDs')
	recalc_group.add_argument('graphid', help='graph id from DB.')

	enum_group = subparsers.add_parser('enum', formatter_class=argparse.RawDescriptionHelpFormatter, help='Enumerate all stuffs', epilog=MSLDAPURLDecoder.help_epilog)
	enum_group.add_argument('ldap_url',  help='Connection specitication in URL format')
	enum_group.add_argument('smb_url',  help='Connection specitication in URL format')
	enum_group.add_argument('-q', '--same-query', action='store_true', help='Use the same query for LDAP as for SMB. LDAP url must still be present, but without a query')
	enum_group.add_argument('--ldap-workers', type=int, default=4, help='LDAP worker count for parallelization')
	enum_group.add_argument('--smb-workers', type=int, default=50, help='SMB worker count for parallelization')
	enum_group.add_argument('--smb-folder-depth', type=int, default=1, help='Files enumeration folder depth')
	enum_group.add_argument('--smb-share-enum', action='store_true', help='Enables file enumeration in shares')
	enum_group.add_argument('-d', '--dns', help='DNS server for resolving IPs')
	enum_group.add_argument('-n', '--do-not-store', action='store_false', help='Skip storing membership and SD info to DB. Will skip edge calculation, and will leave the raw file on disk')
	enum_group.add_argument('-k', '--kerberoast', help='Kerberos URL for kerberoasting')
	enum_group.add_argument('--no-work-dir', action='store_true', help='Skip creating subdirs for temp files')
	enum_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')

	share_group = subparsers.add_parser('shares', help='Enumerate shares on target')
	share_group.add_argument('ad_id', help='ID of the domainfo to poll targets rom the DB')
	share_group.add_argument('smb_url',  help='Credential specitication in URL format')
	share_group.add_argument('--smb-workers', type=int, default=50, help='SMB worker count for parallelization')
	share_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')
	
	smball_group = subparsers.add_parser('smball', help='Enumerate shares on target')
	smball_group.add_argument('ad_id', help='ID of the domainfo to poll targets rom the DB')
	smball_group.add_argument('smb_url',  help='Credential specitication in URL format')
	smball_group.add_argument('--smb-workers', type=int, default=50, help='SMB worker count for parallelization')
	smball_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')

	dns_group = subparsers.add_parser('dns', help='DNS lookup for all hosts')
	dns_group.add_argument('ad_id', help='ID of the domainfo to poll targets rom the DB')
	dns_group.add_argument('dns', help='DNS server for resolving IPs')
	dns_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')

	files_group = subparsers.add_parser('smbfiles', help='Enumerate files on targets')
	files_group.add_argument('ad_id', help='ID of the domainfo to poll targets rom the DB')
	files_group.add_argument('smb_url',  help='Credential specitication in URL format')
	files_group.add_argument('--depth', type=int, default=3, help='Recursion depth for folder enumeration')
	files_group.add_argument('--smb-workers', type=int, default=50, help='SMB worker count for parallelization. Read: connection/share')
	files_group.add_argument('-o', '--out-file', help='Write results to file instead of DB')
	files_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')

	localgroup_group = subparsers.add_parser('localgroups', help='Enumerate local group memberships on target')
	localgroup_group.add_argument('ad_id', help='ID of the domainfo to poll targets rom the DB')
	localgroup_group.add_argument('smb_url',  help='Credential specitication in URL format')
	localgroup_group.add_argument('--smb-workers', type=int, default=50, help='SMB worker count for parallelization')
	localgroup_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')
	
	session_group = subparsers.add_parser('sessions', help='Enumerate connected sessions on target')
	session_group.add_argument('ad_id', help='ID of the domainfo to poll targets rom the DB')
	session_group.add_argument('smb_url',  help='Credential specitication in URL format')
	session_group.add_argument('--smb-workers', type=int, default=50, help='SMB worker count for parallelization')
	session_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')

	kerberoast_group = subparsers.add_parser('kerberoast', help='Kerberoast')
	kerberoast_group.add_argument('ad_id', help='ID of the domainfo to poll targets rom the DB')
	kerberoast_group.add_argument('kerberos_url',  help='Kerberos URL')
	kerberoast_group.add_argument('-x', '--proxy', action='append', help='Proxy URL (multiple for chaining)')
	
	credential_group = subparsers.add_parser('creds', help='Add credential information from impacket')
	credential_group.add_argument('impacket_file', help='file with LM and NT hashes, generated by impacket secretsdump.py')
	credential_group.add_argument('-d', '--domain-id', type=int, default=-1, help='Domain ID to identify the domain')
	
	passwords_group = subparsers.add_parser('passwords', help='Add password information from hashcat potfile')
	passwords_group.add_argument('potfile', help='hashcat potfile with cracked hashes')
	passwords_group.add_argument('--disable-usercheck', action='store_true', help='Disables the user pre-check when inserting to DB. All unique passwords will be uploaded.')
	passwords_group.add_argument('--disable-passwordcheck', action='store_true', help='Disables the password uniqueness check. WILL FAIL IF PW IS ALREADY IN THE DB.')
	
	uncracked_group = subparsers.add_parser('uncracked', help='Polls the DB for uncracked passwords')
	uncracked_group.add_argument('-t', '--hash-type', default='NT', choices=['NT', 'LM'])
	uncracked_group.add_argument('--history', action='store_true', help='Show password history hashes as well')
	uncracked_group.add_argument('-d', '--domain-id', type=int, default=-1, help='Domain ID to identify the domain')

	crateagraphcache_group = subparsers.add_parser('createcache', help='Creates graph cache')
	crateagraphcache_group.add_argument('--backend', default='igraph', choices=['igraph', 'networkx'])
	crateagraphcache_group.add_argument('graph_id', type=int, help='Graph ID to create the graph for')
	
	cracked_group = subparsers.add_parser('cracked', help='Polls the DB for cracked passwords')
	cracked_group.add_argument('-d', '--domain-id', type=int, default=-1, help='Domain ID to identify the domain')

	ws = subparsers.add_parser('ws', help='Suprise tool thats going to help us later')
	ws.add_argument('--listen-ip',  default='127.0.0.1', help='IP address to listen on')
	ws.add_argument('--listen-port',  type=int, default=5001, help='IP address to listen on')
	ws.add_argument('--backend', default='igraph', choices=['igraph', 'networkx'], help='graph backend. Massive performance differences!')
	ws.add_argument('--wsrouter', help='Automatically connect to a WSNET router.')

	bhimport = subparsers.add_parser('bhimport', help='Import bloodhound ingestor data (zip)')
	bhimport.add_argument('bhfile', help='ZIP file generated by sharphound ingestor')

	bhimport2 = subparsers.add_parser('bhimport2', help='New import bloodhound ingestor data (zip)')
	bhimport2.add_argument('-z', '--zip', help='ZIP file generated by sharphound ingestor')
	bhimport2.add_argument('-g', '--graphid', help='Manually specify graph id do add new data to')
	bhimport2.add_argument('-u', '--update', action='store_true', help='Update existing instead of making new')

	args = parser.parse_args()

	asyncio.run(run(args))


if __name__ == '__main__':
	multiprocessing.freeze_support()
	main()
