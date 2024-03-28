import datetime
import socket
import struct

from girder import events, logger, plugin
from girder.exceptions import ValidationException
from girder.models.file import File
from girder.models.notification import Notification, ProgressState
from girder.models.setting import Setting
from girder.utility import setting_utilities

from .constants import PluginSettings


@setting_utilities.validator(PluginSettings.CAV_HOST_PORT)
def validateHostAndPort(doc):
    val = doc['value']
    if val is not None and val != '' and (not isinstance(val, str) or ':' not in val):
        msg = 'The host and port must be of the form <host>:<port>.'
        raise ValidationException(msg, 'value')


@setting_utilities.validator(PluginSettings.CAV_MAX_SCAN_LENGTH)
def validateMaxScanLength(doc):
    val = doc['value']
    if val is not None:
        try:
            doc['value'] = int(val)
            if doc['value'] > 0:
                return
        except ValueError:
            pass  # We want to raise the ValidationException
        raise ValidationException('Max scan length must be None or positive integer.', 'value')


@setting_utilities.validator({
    PluginSettings.CAV_CONNECTION_TIMEOUT,
    PluginSettings.CAV_RESPONSE_TIMEOUT,
})
def validateTimeoutDuration(doc):
    val = doc['value']
    if val is not None:
        try:
            doc['value'] = float(val)
            if doc['value'] > 0:
                return
        except ValueError:
            pass  # We want to raise the ValidationException
        raise ValidationException('Timeout must be None or positive number.', 'value')


def _scan_file(event):
    if 'file' not in event.info or '_id' not in event.info['file']:
        return
    file = File().load(event.info['file']['_id'], force=True)
    if file is None or '_id' not in file:
        return
    try:
        hostAndPort = Setting().get(PluginSettings.CAV_HOST_PORT) or 'clamav:3310'
        host, port = hostAndPort.rsplit(':', 1)
        port = int(port)
        maxScanLength = int(Setting().get(PluginSettings.CAV_MAX_SCAN_LENGTH) or 64 * 1024 ** 2)
        logger.debug(f'CLAMAV: Connecting to clamav at {host}:{port}')
        with socket.create_connection(
            (host, port), float(Setting().get(PluginSettings.CAV_CONNECTION_TIMEOUT) or 30)
        ) as s:
            # TODO: test connection with PING before starting?
            s.settimeout(float(Setting().get(PluginSettings.CAV_RESPONSE_TIMEOUT) or 30))
            logger.debug(f'CLAMAV: Scanning file {file["_id"]}: {file["name"]}')
            s.send(b'zINSTREAM\0')
            chunksize = 256 * 1024
            with File().open(file) as fptr:
                lenread = 0
                while lenread < maxScanLength:
                    chunk = fptr.read(min(chunksize, maxScanLength - lenread))
                    if not len(chunk):
                        break
                    lenread += len(chunk)
                    # logger.debug(
                    #     f'CLAMAV: Sending chunk {len(chunk)} {struct.pack("!I", len(chunk))}')
                    chunk = struct.pack('!I', len(chunk)) + chunk
                    while len(chunk):
                        sent = s.send(chunk)
                        chunk = chunk[sent:]
                        # if len(chunk):
                        #     logger.debug(
                        #         f'CLAMAV: Sending more of chunk {len(chunk)}')
            s.send(b'\0\0\0\0')
            response = s.recv(1024).split(b'\0')[0]
        if response.endswith(b': OK'):
            logger.info(f'CLAMAV: Scanned file {file["_id"]}: {file["name"]}: OK')
            return
        elif response.endswith(b': ERROR'):
            logger.info(f'CLAMAV: Scanned file {file["_id"]}: {file["name"]} '
                        f'errored: {response}; keeping file')
        elif response.endswith(b': FOUND'):
            logger.info(f'CLAMAV: Scanned file {file["_id"]}: {file["name"]} '
                        f'found issue: {response}; deleting file')
            File().remove(file)
            event.info['file'] = None
            Notification().createNotification(
                type='progress',
                data={
                    'title': 'Security threat found',
                    'message': f'File {file["name"]} deleted.',
                    'total': 1,
                    'current': 1,
                    'state': ProgressState.ERROR,
                },
                user=event.info.get('currentUser'),
                expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=30))
        else:
            logger.debug(f'CLAMAV: Scan of file {file["_id"]}: {file["name"]} '
                         f'got unknown response {response}; keeping file')
    except Exception:
        logger.exception('CLAMAV: Failed to scan file with clamav')


class GirderPlugin(plugin.GirderPlugin):
    DISPLAY_NAME = 'ClamAV Scanner'

    def load(self, info):
        # add plugin loading logic here
        events.bind('data.process', 'clamav.scan', _scan_file)
