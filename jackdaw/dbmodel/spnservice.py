from . import Basemodel
import datetime
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from jackdaw.dbmodel.utils.serializer import Serializer


class SPNService(Basemodel, Serializer):
	__tablename__ = 'adspnservices'
	
	id = Column(Integer, primary_key=True)
	ad_id = Column(Integer, ForeignKey('adinfo.id'))
	owner_sid = Column(String, index=True)
	service_class = Column(String, index=True)
	computername = Column(String, index=True)
	port = Column(String, index=True)
	service_name = Column(String, index=True)

	@staticmethod
	def from_spn_str(spn, owner_sid):
		port = None
		service_name = None
		service_class, t = spn.split('/', 1)
		m = t.find(':')
		if m != -1:
			computername, port = t.rsplit(':', 1)
			if port.find('/') != -1:
				port, service_name = port.rsplit('/', 1)
		else:
			computername = t
			if computername.find('/') != -1:
				computername, service_name = computername.rsplit('/', 1)

		s = SPNService()
		s.owner_sid = owner_sid
		s.computername = computername
		s.service_class = service_class
		s.service_name = service_name
		if port is not None:
			s.port = str(port)
		return s

	@staticmethod
	def from_jackdaw_spn(jackdawspn):
		s = SPNService()
		s.owner_sid = jackdawspn.owner_sid
		s.computername = jackdawspn.computername
		s.service_class = jackdawspn.service_class
		s.service_name = jackdawspn.service_name
		if jackdawspn.port is not None:
			s.port = str(jackdawspn.port)
		return s
	