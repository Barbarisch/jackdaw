from . import Basemodel
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
import json
from jackdaw.dbmodel.utils.serializer import Serializer


class Ace(Basemodel, Serializer):
    __tablename__ = 'adaces'

    id = Column(Integer, primary_key=True)
    ad_id = Column(Integer, ForeignKey('adinfo.id'))
    graph_id = Column(Integer, index=True)
    src_sid = Column(String)
    dst_sid = Column(String)
    dst_type = Column(String)
    label = Column(String, index=True)

    def __init__(self, ad_id, graph_id, src, dst, dst_type, label):
        self.ad_id = int(ad_id)
        self.graph_id = graph_id
        self.src_sid = src
        self.dst_sid = dst
        self.dst_type = dst_type
        self.label = label

    @staticmethod
    def from_dict(d):
        return Ace(d['ad_id'], d['graph_id'], d['src_sid'], d['dst_sid'], d['dst_type'], d['label'])

    @staticmethod
    def from_json(x):
        return Ace.from_dict(json.loads(x))

    def to_dict(self):
        return {
            'ad_id': self.ad_id,
            'graph_id': self.graph_id,
            'src': self.src_sid,
            'dst': self.dst_sid,
            'dst_type': self.dst_type,
            'label': self.label
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def from_csv_line(line):
        row = line.split(',')
        return Ace(int(row[1]), int(row[2]), int(row[3]), int(row[4]), row[5], row[6])
