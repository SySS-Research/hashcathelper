from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

_session = None


def get_session(db_uri):
    global _session
    if not _session:
        engine = create_engine(db_uri)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        _session = Session()
    return _session


class Reports(Base):
    __tablename__ = "reports"

    report_id = Column(Integer, primary_key=True)
    submitter_email = Column(String)
    submission_date = Column(DateTime)
    cracking_date = Column(DateTime)

    wordlist = Column(String)
    rule_set = Column(String)
    hashcathelper_version = Column(String)
    hashcat_version = Column(String)

    total_accounts = Column(Integer)
    cracked = Column(Integer)
    unique = Column(Integer)
    user_equals_password = Column(Integer)
    non_empty_lm_hash = Column(Integer)
    empty_password = Column(Integer)
    avg_pw_length = Column(Float)
    largest_baseword_cluster = Column(Integer)
