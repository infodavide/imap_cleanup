#!/usr/bin/python
# -*- coding: utf-8-
"""
Deletion spam and other unwanted messages
"""
import argparse
import atexit
import html
import re
import signal
from datetime import datetime, timedelta
from email import message_from_bytes, message
from email.header import Header

import spamcheck
import imaplib
import logging
import os
import pathlib
import sys
import xml.etree.ElementTree as etree
from logging.handlers import RotatingFileHandler

__author__ = 'David Rolland, contact@infodavid.org'
__copyright__ = 'Copyright © 2024 David Rolland'
__license__ = 'MIT'

IMAP4_PORT: int = 143
IMAP_DATE_FORMAT: str = "%d-%b-%Y"


class _ObjectView:
    """
    Wrapper of the object
    """

    def __init__(self, d):
        """
        Initialize
        :param d: the data
        """
        self.__dict__ = d

    def __str__(self) -> str:
        """ Returns the string representation of the view """
        return str(self.__dict__)


class Rule:
    """
    Rule to use for each message
    """
    delete: bool = False  # True if the message can be deleted
    email = None  # The regular expression to apply on email
    subject = None  # The regular expression to apply on subject

    # noinspection PyShadowingNames
    def __init__(self, delete: bool, email: str, subject: str):
        """
        The constructor
        :param delete: True if the rule is a deletion rule
        :param email: The email value or regular expression
        :param subject: The subject value or regular expression
        """
        self.delete = delete
        if email is not None:
            try:
                self.email = re.compile(email, flags=0)
            except re.error:
                logger.info("%s is not a regular expression", email)
                self.email = email
        if subject is not None:
            try:
                self.subject = re.compile(subject, flags=0)
            except re.error:
                logger.info("%s is not a regular expression", subject)
                self.subject = subject


class Settings:
    """
    Settings used by the IMAP deletion.
    """
    imap_server: str = None  # Full name or IP address of your IMAP server
    imap_use_ssl: bool = False  # Set True to use SSL
    imap_port: int = IMAP4_PORT  # Port of your IMAP server
    imap_user: str = None  # User used to connect to your IMAP server
    imap_password: str = None  # Password (base64 encoded) of the user used to connect to your IMAP server
    imap_folder: str = None  # The IMAP folder where to delete the messages
    imap_trash: str = None  # The IMAP trash folder
    date: datetime.date = None  # The date from which the message are retrieved
    path: str = None  # Path for the files used by the application
    backup_path: str = None  # Path where the messages are stored before deletion, if None, backup is sk
    log_path: str  # Path to the logs file, not used in this version
    log_level: str  # Level of logs, not used in this version
    days: int = 31  # Number of days to analyze
    max_spam_score: float = 9.5  # Maximum spam score
    rules: list[Rule] = []  # List of rules
    dry: bool = False  # True to analyze the message without deleting spam

    def parse(self, path: str) -> None:
        """
        Parse the XML configuration.
        """
        with open(path, encoding='utf-8') as f:
            tree = etree.parse(f)
        root_node: etree.Element = tree.getroot()
        v = root_node.get('date')
        if v is not None:
            self.date = datetime.strptime(v, '%Y-%m-%d').date()
        else:
            self.date = datetime.today()
        v = root_node.get('days')
        if v is not None:
            self.days = int(v)
        else:
            self.days = 31
        v = root_node.get('max-spam-score')
        if v is not None:
            self.max_spam_score = float(v)
        else:
            self.max_spam_score = 9.5
        v = root_node.get('backup-path')
        if v is not None:
            if os.path.isabs(v):
                self.backup_path = v
            else:
                self.backup_path = os.path.splitext(path)[0] + os.sep + v
            if not os.path.exists(self.backup_path):
                os.makedirs(self.backup_path)
        else:
            # noinspection PyTypeChecker
            self.backup_path = None
        log_node: etree.Element = root_node.find('log')
        if log_node is not None:
            v = log_node.get('path')
            if v is not None:
                self.log_path = str(v)
            v = log_node.get('level')
            if v is not None:
                self.log_level = str(v)
        self.rules = []
        for node in tree.findall('rules/rule'):
            v1 = node.get('delete')
            v2 = node.get('email')
            v3 = node.get('subject')
            if v1 is not None and (v2 is not None or v3 is not None):
                self.rules.append(Rule(v1.lower() == 'true', v2, v3))
        accounts = {}
        for node in tree.findall('accounts/account'):
            v1 = node.get('user')
            v2 = node.get('password')
            v3 = node.get('id')
            if v1 is not None and v2 is not None and v3 is not None:
                accounts[v3] = [v1, v2]
        imap_node: etree.Element = root_node.find('imap')
        if imap_node is not None:
            self.imap_server = imap_node.get('server')
            v = imap_node.get('port')
            if v is not None:
                self.imap_port = int(v)
            else:
                self.imap_port = 143
            v = imap_node.get('folder')
            if v is not None:
                self.imap_folder = str(v)
            else:
                self.imap_folder = '"[Gmail]/Sent Mail"'
            v = imap_node.get('trash')
            if v is not None:
                self.imap_trash = str(v)
            else:
                self.imap_trash = '"[Gmail]/Trash"'
            self.imap_use_ssl = imap_node.get('ssl') == 'True' or imap_node.get('ssl') == 'true'
        else:
            raise IOError('No imap element specified in the XML configuration, refer to the XML schema')
        account_id: str = imap_node.get('account-id')
        account = accounts[account_id]
        if account:
            self.imap_user = account[0]
            self.imap_password = account[1]
        self.path = os.path.dirname(path)


def create_rotating_log(path: str, level: str) -> logging.Logger:
    """
    Create the logger with file rotation
    :param path: the path of the main log file
    :param level: the log level as defined in logging module
    :return: the logger
    """
    result: logging.Logger = logging.getLogger("imap_cleanup")
    path_obj: pathlib.Path = pathlib.Path(path)
    if not os.path.exists(path_obj.parent.absolute()):
        os.makedirs(path_obj.parent.absolute())
    if os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            f.close()
    else:
        path_obj.touch()
    # noinspection Spellchecker
    formatter: logging.Formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler: logging.Handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    result.addHandler(console_handler)
    file_handler: logging.Handler = RotatingFileHandler(path, maxBytes=1024 * 1024 * 5, backupCount=5)
    # noinspection PyUnresolvedReferences
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    result.addHandler(file_handler)
    # noinspection PyUnresolvedReferences
    result.setLevel(level)
    return result


def cleanup() -> None:
    """
    Cleanup the instances and session
    """
    logger.log(logging.INFO, "Cleaning...")
    if 'mailbox' in globals():
        if 'logger' in globals():
            logger.info('IMAP session state: %s', mailbox.state)
        if mailbox.state == 'SELECTED':
            mailbox.expunge()
            mailbox.close()
            mailbox.logout()


# pylint: disable=missing-type-doc
def signal_handler(sig=None, frame=None) -> None:
    """
    Trigger the cleanup when program is exited
    :param sig: the signal
    :param frame: the frame
    """
    cleanup()
# pylint: enable=missing-type-doc


# noinspection PyShadowingNames
def process(msg: message.Message) -> (bool, str, str):
    """
    Check if the message is valid and must be kept in the mailbox
    :param msg: the message
    :return: true if the message is valid and must be kept
    """
    value = msg['Reply-To'] or msg['From']
    sender_address: str = ''
    if isinstance(value, bytes):
        sender_address = value.decode('utf-8')
    else:
        sender_address = str(value)
    if '<' in sender_address:
        sender_address = (sender_address.split('<'))[1].split('>')[0]
    if ' ' in sender_address:
        sender_address = (sender_address.split(' '))[0]
    # noinspection PyShadowingNames
    subject: str = str(msg['Subject'])
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Processing message '%s' from %s...", subject, sender_address)
    # noinspection PyTypeChecker
    matching_rule: Rule = None
    result: bool = True
    for rule in settings.rules:
        if isinstance(rule.email, re.Pattern):
            if (matching_rule is None or not rule.delete) and rule.email.match(sender_address):
                if rule.delete:
                    logger.info('Mail from ' + sender_address + ' matches the email rule expression: ' + rule.email.pattern + ' and is marked for deletion')
                else:
                    logger.debug('Mail from ' + sender_address + ' matches the email rule expression: ' + rule.email.pattern + ' and is marked as valid')
                matching_rule = rule
        elif isinstance(rule.email, str):
            if (matching_rule is None or not rule.delete) and rule.email == sender_address:
                if rule.delete:
                    logger.info('Mail from ' + sender_address + ' matches the email rule: ' + rule.email + ' and is marked for for deletion')
                else:
                    logger.debug('Mail from ' + sender_address + ' matches the email rule: ' + rule.email + ' and is marked as valid')
                matching_rule = rule
    for rule in settings.rules:
        if isinstance(rule.subject, re.Pattern):
            if (matching_rule is None or not rule.delete) and rule.subject.match(subject):
                if rule.delete:
                    logger.info('Mail from ' + sender_address + ' matches the subject rule expression: ' + rule.subject.pattern + ' and is marked for for deletion')
                else:
                    logger.debug('Mail from ' + sender_address + ' matches the subject rule expression: ' + rule.subject.pattern + ' and is marked as valid')
                matching_rule = rule
        elif isinstance(rule.subject, str):
            if (matching_rule is None or not rule.delete) and rule.subject == subject:
                if rule.delete:
                    logger.info('Mail from ' + sender_address + ' matches the subject rule: ' + rule.subject + ' and is marked for for deletion')
                else:
                    logger.debug('Mail from ' + sender_address + ' matches the subject rule: ' + rule.subject + ' and is marked as valid')
                matching_rule = rule
    if matching_rule is None:
        result = not is_spam(msg)
    else:
        result = not matching_rule.delete
    return result, sender_address, subject


# noinspection PyShadowingNames
def is_spam(msg: message.Message) -> bool:
    """
    Check if the message is a spam
    :param msg: the message
    :return: true if the message is a spam
    """
    # pylint: disable=unused-variable
    # noinspection PyTypeChecker
    body: str = None
    # pylint: enable=unused-variable
    if msg.is_multipart():
        for part in msg.walk():
            content_type: str = part.get_content_type()
            content_disposition: str = str(part.get('Content-Disposition'))
            # skip any text/plain (txt) attachments
            if content_type == 'text/plain' and 'attachment' not in content_disposition:
                try:
                    body = html.escape(str(part.get_payload(decode=True), 'utf-8'))  # decode
                except UnicodeDecodeError:
                    body = html.escape(str(part.get_payload(decode=True)))  # decode
                break
    # not multipart - i.e. plain text, no attachments, keeping fingers crossed
    else:
        ctype: str = msg.get_content_type()
        if ctype != 'text/html':
            try:
                body = html.escape(str(msg.get_payload(decode=True), 'utf-8'))
            except UnicodeDecodeError:
                body = html.escape(str(msg.get_payload(decode=True)))  # decode
        else:
            try:
                body = str(msg.get_payload(decode=True), 'utf-8')  # decode
            except UnicodeDecodeError:
                body = str(msg.get_payload(decode=True))  # decode
    if body is None or len(body) == 0:
        return False
    report = spamcheck.check(body, report=True)
    result: bool = float(report['score']) >= settings.max_spam_score
    if result:
        logger.info('Mail from ' + sender + ' has a high spam score of ' + report['score'] + ' and is marked for deletion')
    return result


parser = argparse.ArgumentParser(prog='imap_cleanup.py', description='Delete messages from IMAP server')
parser.add_argument('-f', required=True, help='Configuration file')
parser.add_argument('-l', help='Log level', default='INFO')
parser.add_argument('-v', default=False, action='store_true', help='Verbose')
args = parser.parse_args()
LOG_LEVEL: str = args.l
if LOG_LEVEL.startswith('"') and LOG_LEVEL.endswith('"'):
    LOG_LEVEL = LOG_LEVEL[1:-1]
if LOG_LEVEL.startswith("'") and LOG_LEVEL.endswith("'"):
    LOG_LEVEL = LOG_LEVEL[1:-1]
CONFIG_PATH: str = args.f
if CONFIG_PATH.startswith('"') and CONFIG_PATH.endswith('"'):
    CONFIG_PATH = CONFIG_PATH[1:-1]
if CONFIG_PATH.startswith("'") and CONFIG_PATH.endswith("'"):
    CONFIG_PATH = CONFIG_PATH[1:-1]
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = str(pathlib.Path(__file__).parent) + os.sep + CONFIG_PATH
LOG_PATH: str = os.path.splitext(CONFIG_PATH)[0] + '.log'
settings: Settings = Settings()
settings.log_path = LOG_PATH
settings.log_level = LOG_LEVEL
settings.parse(os.path.abspath(CONFIG_PATH))
logger = create_rotating_log(settings.log_path, settings.log_level)
logger.info('Using arguments: %s', repr(args))

if not args.f or not os.path.isfile(args.f):
    print('Input file is required and must be valid.')
    sys.exit(1)

LOCK_PATH: str = os.path.abspath(os.path.dirname(CONFIG_PATH)) + os.sep + '.imap_deletion.lck'
logger.info('Log level set to: %s', logging.getLevelName(logger.level))
atexit.register(signal_handler)
signal.signal(signal.SIGINT, signal_handler)
logger.info('Connecting to server: %s:%s with user: %s', settings.imap_server, str(settings.imap_port), settings.imap_user)

if settings.imap_use_ssl:
    mailbox = imaplib.IMAP4_SSL(host=settings.imap_server, port=settings.imap_port)
else:
    mailbox = imaplib.IMAP4(host=settings.imap_server, port=settings.imap_port)

mailbox.login(settings.imap_user, settings.imap_password)
buffer: str = 'Available folders:\n'
for i in mailbox.list()[1]:
    p = i.decode().split(' "/" ')
    if len(p) > 1:
        buffer += (p[0] + " = " + p[1]) + '\n'
    else:
        buffer += p[0] + '\n'
logger.log(logging.INFO, buffer)
logger.info('Using %s rules', str(len(settings.rules)))
logger.info('Selecting folder: %s', settings.imap_folder)
processed_messages: int = 0
deleted_messages: int = 0
now = datetime.now()
date: datetime.date = (settings.date - timedelta(days=settings.days - 1))
before_date: datetime.date = settings.date
while before_date > date:
    since_date: datetime.date = (before_date - timedelta(days=1))
    logger.info('Searching messages using: SINCE "%s" BEFORE "%s" UNSEEN UNANSWERED', since_date.strftime(IMAP_DATE_FORMAT), before_date.strftime(IMAP_DATE_FORMAT))
    mailbox.select(settings.imap_folder)
    typ, data = mailbox.search(None, f'(SINCE "{since_date.strftime(IMAP_DATE_FORMAT)}" BEFORE "{before_date.strftime(IMAP_DATE_FORMAT)}" UNANSWERED)')
    before_date = (before_date - timedelta(days=1))

    for num in data[0].split():
        _, data = mailbox.fetch(num, '(RFC822)')
        if data is None or data[0] is None:
            continue
        processed_messages += 1
        msg = message_from_bytes(data[0][1])
        (valid, sender, subject) = process(msg)
        if not valid:
            deleted_messages += 1
            if settings.dry:
                logger.info("Message '%s' from %s marked for deletion", subject, sender)
            else:
                if settings.backup_path is not None and len(settings.backup_path) > 0 and 'Message-Id' in msg:
                    sent_date = None
                    if 'Date' in msg:
                        v = msg['Date'].split("(")[0].strip()
                        try:
                            sent_date = datetime.strptime(v, "%a, %d %b %Y %H:%M:%S %z")
                        except ValueError:
                            try:
                                sent_date = datetime.strptime(v, "%d %b %Y %H:%M:%S %z")
                            except ValueError:
                                logger.exception("Could not parse the date: %s", v)
                    if sent_date is not None:
                        path = settings.backup_path + os.sep + str(sent_date.year) + os.sep + str(sent_date.month)
                        if not os.path.exists(path):
                            os.makedirs(path)
                        path = path + os.sep + re.sub(r'\W+', '', msg['Message-Id']) + '.eml'
                        with open(path, mode='wb') as f:
                            f.write(data[0][1])
                        logger.warning("Message '%s' from: %s saved to %s", subject, sender, path)
                logger.warning("Deleting message '%s' from: %s", subject, sender)
                mailbox.store(num, '+FLAGS', '\\Deleted')
if deleted_messages > 0:
    mailbox.select(settings.imap_trash)  # select all trash
logger.info('Processed messages: %s', str(processed_messages))
logger.info('Deleted messages: %s', str(deleted_messages))
sys.exit(0)
