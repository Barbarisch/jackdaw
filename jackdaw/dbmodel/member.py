from . import Basemodel
import datetime
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
import json
from jackdaw.dbmodel.utils.serializer import Serializer


class Member(Basemodel, Serializer):
    __tablename__ = 'admembers'

    id = Column(Integer, primary_key=True)
    ad_id = Column(Integer, ForeignKey('adinfo.id'))
    graph_id = Column(Integer, index=True)
    group_sid = Column(String)
    member_sid = Column(String)
    member_type = Column(String, index=True)

    def __init__(self, ad_id, graph_id, src, dst, member_type):
        self.ad_id = int(ad_id)
        self.graph_id = graph_id
        self.group_sid = src
        self.member_sid = dst
        self.member_type = member_type

    @staticmethod
    def from_dict(d):
        return Member(d['ad_id'], d['graph_id'], d['group_sid'], d['member_sid'], d['member_type'])

    @staticmethod
    def from_json(x):
        return Member.from_dict(json.loads(x))

    def to_dict(self):
        return {
            'ad_id': self.ad_id,
            'graph_id': self.graph_id,
            'group_sid': self.group_sid,
            'member_sid': self.member_sid,
            'member_type': self.member_type
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def from_csv_line(line):
        row = line.split(',')
        return Member(int(row[1]), int(row[2]), int(row[3]), int(row[4]), row[5])
