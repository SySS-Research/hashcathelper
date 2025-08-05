import logging
import re

from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

_session = None

log = logging.getLogger(__name__)


def get_session(db_uri):
    assert db_uri
    global _session
    if not _session:
        db_uri_sanitized = re.sub(
            "://(?P<user>[^:]*):[^@]*@", r"://\g<user>:***@", db_uri
        )
        log.info("Connection to database: %s" % db_uri_sanitized)
        engine = create_engine(db_uri)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        _session = Session()
    return _session


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    submitter_email = Column(String)
    submission_date = Column(DateTime)
    cracking_date = Column(DateTime)

    wordlist = Column(String)
    rule_set = Column(String)
    hashcathelper_version = Column(String)
    hashcat_version = Column(String)

    accounts = Column(Integer)
    cracked = Column(Integer)
    nonunique = Column(Integer)
    user_equals_password = Column(Integer)
    lm_hash_count = Column(Integer)
    empty_password = Column(Integer)
    average_password_length = Column(Float)
    largest_baseword_cluster = Column(Integer)

    def columns_to_dict(self):
        dict_ = {}
        for key in self.__mapper__.c.keys():
            dict_[key] = getattr(self, key)
        return dict_


def submit(session, short_report):
    r = Report(**short_report)
    session.add(r)
    session.commit()
    return r.id
