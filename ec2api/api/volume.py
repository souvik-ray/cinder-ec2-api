# Copyright 2014
# The Cloudscaling Group, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cinderclient import exceptions as cinder_exception
from novaclient import exceptions as nova_exception

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


"""Volume related API implementation
"""


Validator = common.Validator


def create_volume(context, size=None,
                  snapshot_id=None,
                  name=None,description=None):
    #if snapshot_id is not None:
    #    snapshot = ec2utils.get_db_item(context, snapshot_id)
    #    os_snapshot_id = snapshot['os_id']
    #else:
    #    os_snapshot_id = None
    cinder = clients.cinder(context)
    if size is None :
       size=0
    if snapshot_id is not None:
       os_snapshot=cinder.backups.get(snapshot_id)
       snap_size=os_snapshot.size
       if snap_size >size :
           size=snap_size
    with common.OnCrashCleaner() as cleaner:
        os_volume = cinder.volumes.create(
            size,name=name,description=description)
        cleaner.addCleanup(os_volume.delete)
        volume = db_api.add_item(context, 'vol', {'os_id': os_volume.id})
        cleaner.addCleanup(db_api.delete_item, context, volume['id'])
        if snapshot_id is not None:
              import time
              time.sleep(5)
              os_volume=cinder.restores.restore(backup_id=snapshot_id,volume_id=os_volume.id)
#        if snapshot_id is not None:
#              os_volume.update(display_name=snapshot_id)
        #os_volume.update(display_name=name)
        #os_volume.update(name=name)
        #os_volume.update(description=volume['id'])
    return True
    #return _format_volume(context, volume, os_volume, snapshot_id=snapshot_id)

def attach_volume(context, volume_id, instance_id, device):
    volume = ec2utils.get_db_item(context, volume_id)
    instance = ec2utils.get_db_item(context, instance_id)

    nova = clients.nova(context)
    try:
        nova.volumes.create_server_volume(instance['os_id'], volume['os_id'],
                                          device)
    except (nova_exception.Conflict, nova_exception.BadRequest):
        # TODO(andrey-mp): raise correct errors for different cases
        raise exception.UnsupportedOperation()
    cinder = clients.cinder(context)
    os_volume = cinder.volumes.get(volume['os_id'])
    return _format_attachment(context, volume, os_volume,
                              instance_id=instance_id)


def detach_volume(context, volume_id, instance_id=None, device=None,
                  force=None):
    volume = ec2utils.get_db_item(context, volume_id)

    cinder = clients.cinder(context)
    os_volume = cinder.volumes.get(volume['os_id'])
    os_instance_id = next(iter(os_volume.attachments), {}).get('server_id')
    if not os_instance_id:
        # TODO(ft): Change the message with the real AWS message
        reason = _('Volume %(vol_id)s is not attached to anything')
        raise exception.IncorrectState(reason=reason % {'vol_id': volume_id})

    nova = clients.nova(context)
    nova.volumes.delete_server_volume(os_instance_id, os_volume.id)
    os_volume.get()
    instance_id = next((i['id'] for i in db_api.get_items(context, 'i')
                        if i['os_id'] == os_instance_id), None)
    return _format_attachment(context, volume, os_volume,
                              instance_id=instance_id)


def delete_volume(context, volume_id):
    #volume = ec2utils.get_db_item(context, volume_id)
    cinder = clients.cinder(context)
    #pra=open('/tmp/pra2.log','a')
    #pra.write("\n++++ volume['os_id'] is %s "%(volume['os_id']))
    try:
        cinder.volumes.delete(volume_id)
        #cinder.volumes.delete(os_volume)
    except cinder_exception.BadRequest:
        # TODO(andrey-mp): raise correct errors for different cases
        raise exception.UnsupportedOperation()
    except cinder_exception.NotFound:
        pass
    os_volume = cinder.volumes.get(volume_id)
    # NOTE(andrey-mp) Don't delete item from DB until it disappears from Cloud
    # It will be deleted by describer in the future
    return _format_volume_delete(context,os_volume)


class VolumeDescriber(common.TaggableItemsDescriber):

    KIND = 'vol'
    SORT_KEY = 'volumeId'
    FILTER_MAP = {
                  'create-time': 'createTime',
                  'size': 'size',
                  'snapshot-id': 'snapshotId',
                  'status': 'status',
                  'name': 'name',
                  'volume-id': 'volumeId',
                  'attachment.device': ['attachmentSet', 'device'],
                  'attachment.instance-id': ['attachmentSet', 'instanceId'],
                  'attachment.status': ['attachmentSet', 'status']}

    def format(self, volume, os_volume):
        return _format_volume(self.context, volume, os_volume,
                              self.instances, self.snapshots)

    def get_db_items(self):
        self.instances = {i['os_id']: i
                          for i in db_api.get_items(self.context, 'i')}
        self.snapshots = {s['os_id']: s
                          for s in db_api.get_items(self.context, 'snap')}
        return super(VolumeDescriber, self).get_db_items()

    def get_os_items(self):
        return clients.cinder(self.context).volumes.list()

    def get_name(self, os_item):
        return ''

class VolumeDescriberNoDetail(common.TaggableItemsDescriber):

    KIND = 'vol'
    SORT_KEY = 'volumeId'
    FILTER_MAP = {
                  'status': 'status',
                  'name': 'name',
                  'volume-id': 'volumeId'}

    def format(self, volume, os_volume):
        #return _format_volume_delete(self.context,  os_volume)
        return _format_volume_no_detail(self.context, volume, os_volume,
                              self.instances, self.snapshots)

    def get_db_items(self):
        self.instances = {i['os_id']: i
                          for i in db_api.get_items(self.context, 'i')}
        self.snapshots = {s['os_id']: s
                          for s in db_api.get_items(self.context, 'snap')}
        return super(VolumeDescriberNoDetail, self).get_db_items()

    def get_os_items(self):
        return clients.cinder(self.context).volumes.list()

    def get_name(self, os_item):
        return ''


def describe_volumes(context, volume_id=None,detail=False,
                     limit=None, marker=None):
    if volume_id and max_results:
        msg = _('The parameter volumeSet cannot be used with the parameter '
                'maxResults')
        raise exception.InvalidParameterCombination(msg)
    cinder = clients.cinder(context)
    if volume_id is not None : 
        os_volume = cinder.volumes.get(volume_id)
    if detail==True or volume_id is not None:
        formatted_volumes = VolumeDescriber().describe(
             context, ids=volume_id,max_results=limit,next_token=marker)
    else : 
        formatted_volumes = VolumeDescriberNoDetail().describe(
             context, ids=volume_id,max_results=limit,next_token=marker)
    return {'volumeSet': formatted_volumes}

def _format_volume_delete(context, os_volume):
    valid_ec2_api_volume_status_map = {
        'attaching': 'in-use',
        'detaching': 'in-use',
        'in-use': 'in-use',
        'deleting': 'deleting',
        'backingup': 'in-use'}

    ec2_volume = {
            'status': valid_ec2_api_volume_status_map.get(os_volume.status,
                                                          os_volume.status),
    }

    return ec2_volume

def _format_volume_no_detail(context, volume, os_volume, instances={},
                   snapshots={}, snapshot_id=None):
    valid_ec2_api_volume_status_map = {
        'attaching': 'in-use',
        'detaching': 'in-use'}

    ec2_volume = {
            'volumeId': os_volume.id,
            'status': valid_ec2_api_volume_status_map.get(os_volume.status,
                                                          os_volume.status),
            'name': os_volume.name,
    }

    return ec2_volume

def _format_volume(context, volume, os_volume, instances={},
                   snapshots={}, snapshot_id=None):
    valid_ec2_api_volume_status_map = {
        'attaching': 'in-use',
        'detaching': 'in-use'}

    ec2_volume = {
            'volumeId': os_volume.id,
            'status': valid_ec2_api_volume_status_map.get(os_volume.status,
                                                          os_volume.status),
            'size': os_volume.size,
            'name': os_volume.name,
            'description': os_volume.description,
            'createTime': os_volume.created_at,
    }
    if ec2_volume['status'] == 'in-use':
        ec2_volume['attachmentSet'] = (
                [_format_attachment(context, volume, os_volume, instances)])
    else:
        ec2_volume['attachmentSet'] = {}
    if snapshot_id is None and os_volume.snapshot_id:
        snapshot = ec2utils.get_db_item_by_os_id(
                context, 'snap', os_volume.snapshot_id, snapshots)
        snapshot_id = snapshot['id']
    ec2_volume['snapshotId'] = snapshot_id
    #ec2_volume['name'] = os_volume.get('name')

    return ec2_volume


def _format_attachment(context, volume, os_volume, instances={},
                       instance_id=None):
    os_attachment = next(iter(os_volume.attachments), {})
    os_instance_id = os_attachment.get('server_id')
    if not instance_id and os_instance_id:
        instance = ec2utils.get_db_item_by_os_id(
                context, 'i', os_instance_id, instances)
        instance_id = instance['id']
    ec2_attachment = {
            'device': os_attachment.get('device'),
            'instanceId': instance_id,
            'status': (os_volume.status
                       if os_volume.status in ('attaching', 'detaching') else
                       'attached' if os_attachment else 'detached'),
            'volumeId': volume['id']}
    return ec2_attachment
