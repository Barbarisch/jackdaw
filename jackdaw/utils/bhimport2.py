from tqdm import tqdm
import zipfile
import sys
import random
import time

from jackdaw import logger
from jackdaw.dbmodel import *
from jackdaw.dbmodel.adinfo import ADInfo
from jackdaw.dbmodel.adcomp import Machine
from jackdaw.dbmodel.aduser import ADUser
from jackdaw.dbmodel.adgroup import Group
from jackdaw.dbmodel.adou import ADOU


JSON_TYPE_TOP_OBJECT = 1  # top level object
JSON_TYPE_TOP_NEXT = 2  # top level array
JSON_TYPE_ENTRY = 3  # object in top level array
JSON_TYPE_ENTRY_VALUE = 4  # objects, arrays, values in object in top level array
JSON_TYPE_ENTRY_VALUE_ENTRY = 5


def convert_to_dt(s):
    if not isinstance(s, int):
        if s is None or s.lower() == 'none':
            return None
        if isinstance(s, str):
            if s.startswith('TMSTMP-') is True:
                s = s.replace('TMSTMP-', '')
            elif s == 'Never':
                s = -1
        try:
            s = int(s)
        except:
            logger.debug('Datetime conversion failed for value %s' % s)
            return None
    return datetime.datetime.utcfromtimestamp(s)


class BHImport2:
    def __init__(self, db_conn=None, db_session=None):
        self.debug = False
        self.json_files = []
        self.db_conn = db_conn
        self.db_session = db_session
        self.json_parser = JsonParser(self)
        self.gi = None
        self.graphid = 0

        self.ads = {}
        self.adn = {}  # name -> ad_id

        random.seed(time.time())

    def setup_db(self):
        if self.db_session is None:
            self.db_session = get_session(self.db_conn)

    def rando(self):
        min_ = 2147483647
        max_ = 4294967295
        rand = random.randint(min_, max_)
        return rand

    def sid_to_id(self, sid, adid, objtype='unknown'):
        res = self.db_session.query(EdgeLookup).filter_by(oid=sid).filter(EdgeLookup.ad_id == adid).first()
        if res:
            return res.id
        else:
            # print('WTF', sid, adid)
            # input()
            edgeinfo = EdgeLookup(adid, sid, objtype)
            self.db_session.add(edgeinfo)
            self.db_session.commit()
            self.db_session.refresh(edgeinfo)
            return edgeinfo.id

    def json_handler(self, json_type, bh_version, entries):
        if bh_version == 4 or bh_version == 3:
            if json_type == 'domains':
                self.import_domain_v4(bh_version, entries)
            elif json_type == 'gpos':
                self.import_gpo_v4(bh_version, entries)
            elif json_type == 'ous':
                self.import_ou_v4(bh_version, entries)
            elif json_type == 'containers':
                self.import_container_v4(bh_version, entries)
            elif json_type == 'groups':
                self.import_group_v4(bh_version, entries)
            elif json_type == 'computers':
                self.import_machine_v4(bh_version, entries)
            elif json_type == 'users':
                self.import_user_v4(bh_version, entries)
            else:
                print('Unsupported collection type', json_type)
                input()
        else:
            pass
            # print(f'Unsupported bloodhound version {bh_version}')

    def import_domain_v4(self, bh_version, entries):
        gi = GraphInfo('bloodhound import')

        self.db_session.add(gi)
        self.db_session.commit()
        self.db_session.refresh(gi)
        self.graphid = gi.id

        objects = entries['objects']
        arrays = entries['arrays']
        values = entries['values']


        # isaclprotected = values['IsACLProtected']
        # isdeleted = values['IsDeleted']
        objectid = values['ObjectIdentifier']

        di = ADInfo()

        if 'Properties' in objects.keys():
            values = objects['Properties']['values']
            di.name = values['name']
            di.objectSid = objectid
            di.distinguishedName = values['distinguishedname']
            if 'whencreated' in values:
                di.whenCreated = convert_to_dt(values['whencreated'])
            # skipped Properties: domain, description, functionallevel

        # di.gen_checksum()

        self.db_session.add(di)
        self.db_session.commit()
        self.db_session.refresh(di)
        self.ad_id = di.id

        edgeinfo = EdgeLookup(self.ad_id, objectid, 'domain')
        self.db_session.add(edgeinfo)
        self.db_session.commit()

        self.ads[objectid] = di.id
        self.adn[di.name.lower()] = di.id

        giad = GraphInfoAD(self.ad_id, self.graphid)
        self.db_session.add(giad)
        self.db_session.commit()

        # add aces to global Ace table (these will be turned into edges later)
        if 'Aces' in arrays.keys():
            if len(arrays['Aces']) > 0:
                aces = arrays['Aces']['objects']
                for _, ace in aces.items():
                    values = ace['values']
                    dst = values['PrincipalSID']
                    dst_type = values['PrincipalType']
                    label = values['RightName']
                    newace = Ace(di.id, self.graphid, objectid, dst, dst_type, label)
                    self.db_session.add(newace)

        # skipped: ChildObjects
        # TODO: Trusts, Links

        self.db_session.commit()

    def import_group_v4(self, bh_version, entries):
        try:
            objects = entries['objects']
            arrays = entries['arrays']
            values = entries['values']

            if 'ObjectIdentifier' not in values:
                print('import_group_v4, no objectidentifier', entries)
                return

            # isaclprotected = values['IsACLProtected']
            # isdeleted = values['IsDeleted']
            objectid = values['ObjectIdentifier']

            # if objectid == 'S-1-5-21-3937601378-3721788405-2067139823-512':
            #    print('HERE!!', arrays)
            #    input()

            m = Group()

            if 'Properties' in objects.keys():
                values = objects['Properties']['values']

                if 'domainsid' in values:
                    m.ad_id = self.ads[values['domainsid']]
                else:
                    domain_name = values['domain'].lower()
                    if domain_name not in self.adn:
                        # print('TODO', values, objectid)
                        # input()
                        # TODO...domain trusts maybe
                        return
                    m.ad_id = self.adn[domain_name]

                m.name = values['name'].split('@', 1)[0]
                m.sAMAccountName = m.name
                m.cn = m.name
                m.objectSid = objectid

                # m.objectSid, _, m.oid, is_domainsid = self.breakup_groupsid(groups['ObjectIdentifier'], m.ad_id)
                # if is_domainsid is False:
                #    print('localgroup! %s' % m.oid)

                if 'description' in values and values['description']:
                    m.description = values['description']
                if 'distinguishedname' in values and values['distinguishedname']:
                    m.dn = values['distinguishedname']
                if 'admincount' in values:
                    m.adminCount = values['admincount']
                if 'whencreated' in values:
                    m.whenCreated = convert_to_dt(values['whencreated'])
            # m.gen_checksum()

            if m.ad_id is None:
                return

            self.db_session.add(m)
            edgeinfo = EdgeLookup(m.ad_id, objectid, 'group')
            self.db_session.add(edgeinfo)

            if 'Members' in arrays.keys():
                if len(arrays['Members']) > 0:
                    members = arrays['Members']['objects']
                    for _, member in members.items():
                        values = member['values']
                        if bh_version == 4:
                            member_sid = values['ObjectIdentifier']
                            member_type = values['ObjectType']
                            newmember = Member(m.ad_id, self.graphid, objectid, member_sid, member_type)
                            self.db_session.add(newmember)
                        elif bh_version == 3:
                            member_sid = values['MemberId']
                            member_type = values['MemberType']
                            newmember = Member(m.ad_id, self.graphid, objectid, member_sid, member_type)
                            self.db_session.add(newmember)

            if 'Aces' in arrays.keys():
                if len(arrays['Aces']) > 0:
                    aces = arrays['Aces']['objects']
                    for _, ace in aces.items():
                        values = ace['values']
                        dst = values['PrincipalSID']
                        dst_type = values['PrincipalType']
                        label = values['RightName']
                        newace = Ace(m.ad_id, self.graphid, objectid, dst, dst_type, label)
                        self.db_session.add(newace)

            self.db_session.commit()
        except Exception as ex:
            print('import_group_v4', ex)

    def import_user_v4(self, bh_version, entries):
        try:
            objects = entries['objects']
            arrays = entries['arrays']
            values = entries['values']

            if 'ObjectIdentifier' not in values:
                print('import_user_v4, no objectidentifier', entries)
                return

            # isaclprotected = values['IsACLProtected']
            # isdeleted = values['IsDeleted']
            objectid = values['ObjectIdentifier']
            # primarygroupsid = values['PrimaryGroupSID']

            m = ADUser()
            if 'Properties' in objects.keys():
                values = objects['Properties']['values']

                if 'domainsid' in values:
                    m.ad_id = self.ads[values['domainsid']]
                else:
                    domain_name = values['domain'].lower()
                    if domain_name not in self.adn:
                        # print('TODO', values, objectid)
                        # input()
                        # TODO...domain trusts maybe
                        return
                    m.ad_id = self.adn[domain_name]
                m.name = values['name'].split('@', 1)[0]
                m.cn = m.name
                m.sAMAccountName = m.name
                m.objectSid = objectid
                if 'distinguishedname' in values and values['distinguishedname']:
                    m.dn = values['distinguishedname']
                if 'description' in values and values['description']:
                    m.description = values['description']
                if 'displayname' in values and values['displayname']:
                    m.displayName = values['displayname']
                if 'email' in values and values['email']:
                    m.email = values['email']
                if 'dontreqpreauth' in values:
                    m.UAC_DONT_REQUIRE_PREAUTH = values['dontreqpreauth']
                if 'passwordnotreqd' in values:
                    m.UAC_PASSWD_NOTREQD = values['passwordnotreqd']
                if 'unconstraineddelegation' in values:
                    m.UAC_TRUSTED_FOR_DELEGATION = values['unconstraineddelegation']
                if 'enabled' in values:
                    m.canLogon = values['enabled']
                if 'pwdneverexpires' in values:
                    m.UAC_DONT_EXPIRE_PASSWD = values['pwdneverexpires']
                if 'admincount' in values:
                    m.adminCount = values['admincount']
                if 'pwdlastset' in values:
                    m.pwdLastSet = convert_to_dt(values['pwdlastset'])
                if 'lastlogontimestamp' in values:
                    m.lastLogonTimestamp = convert_to_dt(values['lastlogontimestamp'])
                if 'lastlogon' in values:
                    m.lastLogon = convert_to_dt(values['lastlogon'])
                if 'whencreated' in values:
                    m.whenCreated = convert_to_dt(values['whencreated'])
            # m.gen_checksum()

            self.db_session.add(m)
            edgeinfo = EdgeLookup(m.ad_id, objectid, 'user')
            self.db_session.add(edgeinfo)

            if 'Aces' in arrays.keys():
                if len(arrays['Aces']) > 0:
                    aces = arrays['Aces']['objects']
                    for _, ace in aces.items():
                        values = ace['values']
                        dst = values['PrincipalSID']
                        dst_type = values['PrincipalType']
                        label = values['RightName']
                        newace = Ace(m.ad_id, self.graphid, objectid, dst, dst_type, label)
                        self.db_session.add(newace)

            self.db_session.commit()
        except Exception as ex:
            print('import_user_v4', ex)

    def import_machine_v4(self, bh_version, entries):
        try:
            objects = entries['objects']
            arrays = entries['arrays']
            values = entries['values']

            # isaclprotected = values['IsACLProtected']
            # isdeleted = values['IsDeleted']
            if 'ObjectIdentifier' in values:
                objectid = values['ObjectIdentifier']
            else:
                objectid = ''
            # status = values['Status']
            if 'PrimaryGroupSID' in values:
                primarygroupsid = values['PrimaryGroupSID']
            else:
                primarygroupsid = None

            m = Machine()
            if 'Properties' in objects.keys():
                values = objects['Properties']['values']

                if 'domainsid' in values:
                    m.ad_id = self.ads[values['domainsid']]
                else:
                    domain_name = values['domain'].lower()
                    if domain_name not in self.adn:
                        # print('TODO', values, objectid)
                        # input()
                        # TODO...domain trusts maybe
                        return
                    else:
                        m.ad_id = self.adn[domain_name]
                m.name = values['name'].split('.', 1)[0]
                m.displayName = m.name
                m.dn = values['distinguishedname']
                m.canLogon = values['enabled']
                m.lastLogonTimestamp = convert_to_dt(values['lastlogontimestamp'])
                m.pwdLastSet = convert_to_dt(values['pwdlastset'])
                m.dNSHostName = values['name']
                m.cn = values['name'].split('.', 1)[0]
                # temp_account_name = values['name'].split('.', 1)[0] + '$'
                m.sAMAccountName = m.name + '$'
                if len(objectid) == 0:
                    objectid = values['objectid']
                m.objectSid = objectid
                m.UAC_TRUSTED_FOR_DELEGATION = values['unconstraineddelegation']
                if primarygroupsid:
                    m.primaryGroupID = primarygroupsid.split('-')[-1]
                if 'description' in values and values['description']:
                    m.description = values['description']
                if 'operatingsystem' in values and values['operatingsystem']:
                    m.operatingSystem = values['operatingsystem']
                if 'whencreated' in values:
                    m.whenCreated = convert_to_dt(values['whencreated'])
            # m.gen_checksum()
            else:
                # in some cases there isnt a property block...guess pass on those
                return

            self.db_session.add(m)
            edgeinfo = EdgeLookup(m.ad_id, objectid, 'machine')
            self.db_session.add(edgeinfo)

            if 'Aces' in arrays.keys():
                if len(arrays['Aces']) > 0:
                    aces = arrays['Aces']['objects']
                    for _, ace in aces.items():
                        values = ace['values']
                        dst = values['PrincipalSID']
                        dst_type = values['PrincipalType']
                        label = values['RightName']
                        newace = Ace(m.ad_id, self.graphid, objectid, dst, dst_type, label)
                        self.db_session.add(newace)

            self.db_session.commit()
        except Exception as ex:
            print('import_machine_v4', ex)

    def import_gpo_v4(self, bh_version, entries):
        try:
            objects = entries['objects']
            arrays = entries['arrays']
            values = entries['values']

            if 'ObjectIdentifier' not in values:
                return

            # isaclprotected = values['IsACLProtected']
            # isdeleted = values['IsDeleted']
            objectid = values['ObjectIdentifier']

            m = GPO()
            if 'Properties' in objects.keys():
                values = objects['Properties']['values']

                if 'domainsid' in values:
                    m.ad_id = self.ads[values['domainsid']]
                else:
                    domain_name = values['domain'].lower()
                    if domain_name not in self.adn:
                        # print('TODO', values, objectid)
                        # input()
                        # TODO...domain trusts maybe
                        return
                    m.ad_id = self.adn[domain_name]
                m.name = values['name'].split('@', 1)[0]
                m.objectGUID = objectid
                if values['description']:
                    m.description = values['description']
                if 'distinguishedname' in values and values['distinguishedname']:
                    m.dn = values['distinguishedname']
                    m.cn = m.dn.split(',')[0].strip('CN=')
                if values['gpcpath']:
                    m.path = values['gpcpath']
                if 'whencreated' in values:
                    m.whenCreated = convert_to_dt(values['whencreated'])
            # m.gen_checksum()

            self.db_session.add(m)
            edgeinfo = EdgeLookup(m.ad_id, objectid, 'gpo')
            self.db_session.add(edgeinfo)
            self.db_session.commit()

            if 'Aces' in arrays.keys():
                if len(arrays['Aces']) > 0:
                    aces = arrays['Aces']['objects']
                    for _, ace in aces.items():
                        values = ace['values']
                        dst = values['PrincipalSID']
                        dst_type = values['PrincipalType']
                        label = values['RightName']
                        newace = Ace(m.ad_id, self.graphid, objectid, dst, dst_type, label)
                        self.db_session.add(newace)

            self.db_session.commit()
        except Exception as ex:
            print('import_gpo_v4', ex)

    def import_ou_v4(self, bh_version, entries):
        try:
            objects = entries['objects']
            arrays = entries['arrays']
            values = entries['values']

            if 'ObjectIdentifier' not in values:
                return

            # isaclprotected = values['IsACLProtected']
            # isdeleted = values['IsDeleted']
            objectid = values['ObjectIdentifier']

            m = ADOU()

            if 'Properties' in objects.keys():
                values = objects['Properties']['values']

                ad_name = values['domain'].lower()
                if ad_name not in self.adn:
                    # print('TODO', values, objectid)
                    # input()
                    # TODO...domain trusts maybe
                    return
                m.ad_id = self.adn[ad_name]
                m.name = values['name'].split('@', 1)[0]
                m.ou = m.name
                m.objectGUID = objectid
                if values['description']:
                    m.description = values['description']
                if values['distinguishedname']:
                    m.dn = values['distinguishedname']
                if 'whencreated' in values:
                    m.whenCreated = convert_to_dt(values['whencreated'])

            if 'Links' in arrays.keys():
                pass
                # TODO GPO Links!!!!!
                # l = Gplink()
                # l.ad_id = m.ad_id
                # l.ou_guid = m.objectGUID
                # if self.bloodhound_version == '2':
                #    gponame = link['Name'].split('@', 1)[0]
                #    res = self.db_session.query(GPO).filter_by(name=gponame).filter(GPO.ad_id == m.ad_id).first()
                #    if res is None:
                #        logger.debug(
                #            'Could not insert OU link %s. Reason: could not find GPO %s' % (link, link['Name']))
                #        continue
                #    l.gpo_dn = res.objectGUID
                # else:
                #    l.gpo_dn = '{%s}' % link['Guid']
                # self.db_session.add(l)

            self.db_session.add(m)
            edgeinfo = EdgeLookup(m.ad_id, objectid, 'ou')
            self.db_session.add(edgeinfo)
            self.db_session.commit()

            # add aces to global Ace table (these will be turned into edges later)
            if 'Aces' in arrays.keys():
                if len(arrays['Aces']) > 0:
                    aces = arrays['Aces']['objects']
                    for _, ace in aces.items():
                        values = ace['values']
                        dst = values['PrincipalSID']
                        dst_type = values['PrincipalType']
                        label = values['RightName']
                        newace = Ace(m.ad_id, self.graphid, objectid, dst, dst_type, label)
                        self.db_session.add(newace)

            self.db_session.commit()
        except Exception as ex:
            print('import_ou_v4', ex)

    def import_container_v4(self, bh_version, entries):
        pass

    def import_session(self):
        pass

    def insert_spn(self):
        pass

    def insert_edge(self):
        pass

    def insert_all_members(self):
        count = self.db_session.query(Member).count()
        # print('Testing', count)
        test = 0
        iterator = tqdm(range(0, count))

        q = self.db_session.query(Member)
        for member in windowed_query(q, Member.id, 1000):
            dst = self.sid_to_id(member.group_sid, member.ad_id)
            src = self.sid_to_id(member.member_sid, member.ad_id)
            edge = Edge(member.ad_id, self.graphid, src, dst, 'member')
            self.db_session.add(edge)
            test = test + 1
            iterator.update(1)
        self.db_session.commit()

    def insert_all_aces(self):
        # for all aces update principalsiduuid with proper uuid
        # count = self.the_database.get_table_count(Aces)
        count = self.db_session.query(Ace).count()
        # print('Testing', count)
        test = 0
        iterator = tqdm(range(0, count))

        q = self.db_session.query(Ace)
        for ace in windowed_query(q, Ace.id, 1000):
            src = self.sid_to_id(ace.dst_sid, ace.ad_id)
            dst = self.sid_to_id(ace.src_sid, ace.ad_id)
            edge = Edge(ace.ad_id, self.graphid, src, dst, ace.label)
            self.db_session.add(edge)
            test = test + 1
            iterator.update(1)
        self.db_session.commit()

    def from_zipfile(self, filepath):
        with zipfile.ZipFile(filepath, 'r') as myzip:
            for names in myzip.namelist():
                try:
                    sys.stdout.write(f'Unzipping {names} to /tmp/{names}...')
                    myzip.extract(names, f'/tmp/')
                    sys.stdout.write(f'done\n')
                    self.json_files.append(f'/tmp/{names}')
                except Exception as ex:
                    print('Error', ex)

    def readchunk(self, f):
        try:
            return f.read(1024)
        except Exception as ex:
            return ''

    def run(self):
        self.setup_db()

        # for all files in zip get meta information on them first
        all_json_files = {}
        for json_file in self.json_files:
            with open(json_file, 'rb') as f:
                data = f.read()
                data = data[-1000:]
                offset = data.find(b'"meta')
                test = data[offset:-1].strip(b'"meta":')
                meta = json.loads(test)
                all_json_files[meta['type']] = (meta, json_file)
                del data

        print(f'Processing domains json {all_json_files["domains"]}')
        with open(all_json_files['domains'][1], 'r') as f:
            #data = f.read()
            #self.json_parser.json_parser(all_json_files['domains'][0], data)
            #del data
            self.json_parser.json_parser2(all_json_files['domains'][0], f)

        #print('pause')
        #input()

        print(f'Processing groups json {all_json_files["groups"]}')
        with open(all_json_files['groups'][1], 'r') as f:
            self.json_parser.json_parser2(all_json_files['groups'][0], f)
            #data = f.read()
            #self.json_parser.json_parser(all_json_files['groups'][0], data)
            #del data

        #print('pause')
        #input()

        print(f'Processing users json {all_json_files["users"]}')
        with open(all_json_files['users'][1], 'r') as f:
            self.json_parser.json_parser2(all_json_files['users'][0], f)
            #data = f.read()
            #self.json_parser.json_parser(all_json_files['users'][0], data)
            #del data

        #print('pause')
        #input()

        print(f'Processing computers json {all_json_files["computers"]}')
        with open(all_json_files['computers'][1], 'r') as f:
            self.json_parser.json_parser2(all_json_files['computers'][0], f)
            # data = f.read()
            # self.json_parser.json_parser(all_json_files['computers'][0], data)
            # del data

        #print('pause')
        #input()

        print(f'Processing gpos json {all_json_files["gpos"]}')
        with open(all_json_files['gpos'][1], 'r') as f:
            self.json_parser.json_parser2(all_json_files['gpos'][0], f)
            # data = f.read()
            # self.json_parser.json_parser(all_json_files['gpos'][0], data)
            # del data

        #print('pause')
        #input()

        print(f'Processing ous json {all_json_files["ous"]}')
        with open(all_json_files['ous'][1], 'r') as f:
            self.json_parser.json_parser2(all_json_files['ous'][0], f)
            # data = f.read()
            # self.json_parser.json_parser(all_json_files['ous'][0], data)
            # del data

        #print('pause')
        #input()

        # create edges
        print('Creating edges from group memberships')
        self.insert_all_members()
        print('Creating edges from aces')
        self.insert_all_aces()

        # original call order
        # self.setup_db()
        # self.import_domain()
        # self.import_group()
        # self.import_user()
        # self.import_machine()
        # self.import_gpo()
        # self.import_ou()
        # self.import_session()
        # self.insert_spn()
        # self.insert_edge()
        # self.insert_all_acl()
        # self.db_session.commit()


class JsonParser:
    def __init__(self, bhimporter):
        self.bhimporter = bhimporter
        self.iterator = None  # holds tqdm progress tracker
        self.offset = 0  # data offset
        self.data = ''  # raw json data
        self.datalen = 0
        self.bh_version = 0
        self.bh_type = ''  # bloodhound data type (computer, user, group...etc
        self.f = None

    def next_chunk(self):
        # print('Getting next chunk')
        # input()
        return self.bhimporter.readchunk(self.f)

    def get_next_char(self):
        self.offset = self.offset + 1
        if self.offset < self.datalen:
            return self.data[self.offset]
        else:
            self.data = self.next_chunk()
            self.datalen = len(self.data)
            self.offset = 0
            if self.offset < self.datalen:
                char = self.data[self.offset]
                # self.offset = self.offset + 1
                return char
            else:
                return None

    def get_current_char(self):
        if self.offset < self.datalen:
            return self.data[self.offset]
        else:
            self.data = self.next_chunk()
            self.datalen = len(self.data)
            self.offset = 0
            if self.offset < self.datalen:
                return self.data[self.offset]
            else:
                return None

    def json_parser(self, meta, data):
        """ Given raw json bytes start reading from end """
        self.bh_version = meta['version']
        self.bh_type = meta['type']
        self.data = data
        self.datalen = len(data)
        self.offset = 0
        self.iterator = tqdm(range(0, meta['count']))

        # check for byte order mark (BOM)
        if self.data[0] != '{':
            bom = bytes(self.data[0], 'utf-8')
            if bom != b'\xef\xbb\xbf':
                print('FATAL! - not utf-8 encoding. Try another file')
                return
            self.offset = self.offset + 1

        while self.offset < self.datalen:
            char = self.data[self.offset]

            if char == '{':
                _ = self.json_object_parser(json_type=JSON_TYPE_TOP_OBJECT)

            self.offset = self.offset + 1

    def json_parser2(self, meta, f):
        """ Given raw json bytes start reading from end """
        self.bh_version = meta['version']
        self.bh_type = meta['type']
        self.f = f
        self.data = self.next_chunk()
        self.datalen = len(self.data)
        self.offset = 0
        self.iterator = tqdm(range(0, meta['count']))

        # check for byte order mark (BOM)
        if self.data[0] != '{':
            bom = bytes(self.data[0], 'utf-8')
            if bom != b'\xef\xbb\xbf':
                print('FATAL! - not utf-8 encoding. Try another file')
                return
            self.offset = self.offset + 1

        char = self.get_current_char()
        # while self.offset < self.datalen:
        while char is not None:
            # char = self.data[self.offset]

            if char and char == '{':
                _ = self.json_object_parser(json_type=JSON_TYPE_TOP_OBJECT)

            # self.offset = self.offset + 1
            char = self.get_next_char()

    def json_object_parser(self, name='', json_type=JSON_TYPE_ENTRY_VALUE):
        """ Handles the data between '{' and '}' during processing """
        # print('object parser START...', json_type)
        entries = {}

        char = self.get_current_char()
        if char != '{':
            print('Error bad object', self.offset, self.data[self.offset])
            return
        else:
            # self.offset = self.offset + 1
            char = self.get_next_char()
            # while self.offset < self.datalen:
            while char is not None:
                # if self.data[self.offset] == '}':
                if char == '}':
                    # self.offset = self.offset + 1
                    self.get_next_char()

                    if json_type == JSON_TYPE_TOP_NEXT:
                        # special handling of meta object to get version and type (computer, user, group...etc)
                        if name == 'meta':
                            pass
                    elif json_type == JSON_TYPE_ENTRY:
                        self.iterator.update(1)
                        self.bhimporter.json_handler(self.bh_type, self.bh_version, entries)
                        entries.clear()
                    break
                else:
                    entries = self.json_entries_parser(['}'], json_type)
                    char = self.get_current_char()

        # print('object parser END...', name)
        return entries

    def json_array_parser(self, name='', json_type=JSON_TYPE_ENTRY_VALUE):
        """ Handles the data between '[' and ']' during processing """
        # print('array parser START...', json_type)
        entries = {}

        char = self.get_current_char()
        if char != '[':
            print('Error bad array', self.data[self.offset])
            return
        else:
            # self.offset = self.offset + 1
            char = self.get_next_char()
            # while self.offset < self.datalen:
            while char is not None:
                # if self.data[self.offset] == ']':
                if char == ']':
                    # self.offset = self.offset + 1
                    self.get_next_char()

                    # handle completely parsed array
                    if json_type == JSON_TYPE_TOP_NEXT:
                        if name != 'data':
                            pass
                    break
                else:
                    entries = self.json_entries_parser([']'], json_type)
                    char = self.get_current_char()

        # print('array parser END...', name, json_type)
        return entries

    def json_entries_parser(self, end_chars, json_type=JSON_TYPE_ENTRY_VALUE):
        """ Generic parser of JSON data objects, arrays, and values """
        entries = {}
        entries['objects'] = {}
        entries['arrays'] = {}
        entries['values'] = {}

        entry_name = ''
        idx = 0
        char = self.get_current_char()

        # while self.offset < self.datalen:
        while char is not None:
            # print('testing', self.data[self.offset])
            # if self.data[self.offset] in end_chars:  # end of object/arrar
            if char in end_chars:
                break
            # elif self.data[self.offset] == '"':
            elif char == '"':
                temp_str = self.read_json_string()
                char = self.get_current_char()
                # if self.data[self.offset] == ':':
                if char == ':':
                    entry_name = temp_str
                    # self.offset = self.offset + 1
                    char = self.get_next_char()
                else:
                    if entry_name == '':
                        tmp_name = str(self.bhimporter.rando())
                    else:
                        tmp_name = entry_name
                    entries['values'][tmp_name] = temp_str
            # elif self.data[self.offset] == '{':  # new object
            elif char == '{':
                idx = idx + 1
                obj_entries = self.json_object_parser(name=entry_name, json_type=json_type+1)
                if entry_name == '':
                    tmp_name = str(self.bhimporter.rando())
                else:
                    tmp_name = entry_name
                entries['objects'][tmp_name] = obj_entries
                char = self.get_current_char()
            # elif self.data[self.offset] == '[':  # new array
            elif char == '[':
                arr_entries = self.json_array_parser(name=entry_name, json_type=json_type+1)
                if entry_name == '':
                    tmp_name = str(self.bhimporter.rando())
                else:
                    tmp_name = entry_name
                entries['arrays'][tmp_name] = arr_entries
                char = self.get_current_char()
            # elif self.data[self.offset] == ',':  # move to next entry
            elif char == ',':
                # self.offset = self.offset + 1
                char = self.get_next_char()
            else:  # new key/value entry
                entry_value = self.read_json_value(end_chars)
                if entry_name == '':
                    tmp_name = str(self.bhimporter.rando())
                else:
                    tmp_name = entry_name
                entries['values'][tmp_name] = entry_value
                char = self.get_current_char()

        return entries

    def read_json_value(self, end_chars):
        tmp_val = ''
        is_str = False
        ret_val = None

        char = self.get_current_char()
        # while self.offset < self.datalen:
        while char is not None:
            # if self.data[self.offset] == ',' or self.data[self.offset] in end_chars:
            if char == ',' or char in end_chars:
                break
            # elif self.data[self.offset] == '"':
            elif char == '"':
                is_str = True
                tmp_val = self.read_json_string()
                char = self.get_current_char()
            else:
                # tmp_val = tmp_val + self.data[self.offset]
                tmp_val = tmp_val + char
                # self.offset = self.offset + 1
                char = self.get_next_char()

        if len(tmp_val) > 0 and is_str is False:
            try:
                if tmp_val == 'false':
                    ret_val = False
                elif tmp_val == 'true':
                    ret_val = True
                elif tmp_val == 'null':
                    ret_val = None
                else:
                    ret_val = int(tmp_val)
            except Exception as ex:
                ret_val = tmp_val
                print(f'Error: {ex}', self.offset, self.data[self.offset], tmp_val)
                # print('!!!:', self.data[self.offset-120:self.offset+120])
                input()
        elif len(tmp_val) > 0 and is_str is True:
            ret_val = tmp_val
        else:
            print("WTF")
            input()
        # print('Read Value', ret_val)
        return ret_val

    def read_json_string(self):
        ret_str = ''

        char = self.get_current_char()
        # if self.data[self.offset] != '"':
        if char != '"':
            print('Bad string value', self.data[self.offset])
        else:
            # self.offset = self.offset + 1
            char = self.get_next_char()
            # while self.offset < self.datalen:
            while char is not None:
                # if self.data[self.offset] == '\\':
                if char == '\\':
                    # self.offset = self.offset + 1
                    char = self.get_next_char()
                    # ret_str = ret_str + self.data[self.offset]
                    ret_str = ret_str + char
                    # self.offset = self.offset + 1
                    char = self.get_next_char()
                # elif self.data[self.offset] == '"':
                elif char == '"':
                    # self.offset = self.offset + 1
                    self.get_next_char()
                    break
                else:
                    # ret_str = ret_str + self.data[self.offset]
                    ret_str = ret_str + char
                    # self.offset = self.offset + 1
                    char = self.get_next_char()

        # print('Read String', ret_str)
        return ret_str
