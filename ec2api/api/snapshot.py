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

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


"""Snapshot related API implementation
"""


Validator = common.Validator


def create_snapshot(context, volume_id, description=None,name=None):
    #volume = ec2utils.get_db_item(context, volume_id)
    cinder = clients.cinder(context)
    os_volume = cinder.volumes.get(volume_id)
    # NOTE(ft): Easy fix to allow snapshot creation in statuses other than
    # AVAILABLE without cinder modifications. Potential race condition
    # though. Seems arguably non-fatal.
    if os_volume.status not in ['available', 'in-use',
                                'attaching', 'detaching']:
        msg = (_("'%s' is not in a state where snapshots are allowed.") %
               volume_id)
        raise exception.IncorrectState(reason=msg)
    with common.OnCrashCleaner() as cleaner:
        os_snapshot = cinder.backups.create(
                os_volume.id,
                description=description,name=name)
        #os_snapshot = cinder.volume_snapshots.create(
        #        os_volume.id, force=True,
        #        display_description=description)
        cleaner.addCleanup(os_snapshot.delete)
        snapshot = db_api.add_item(context, 'snap', {'os_id': os_snapshot.id})
        cleaner.addCleanup(db_api.delete_item, context, snapshot['id'])
        #os_snapshot.update(display_name=snapshot['id'])

    return _format_snapshot(context, snapshot, os_snapshot,
                            volume_id=volume_id)


def delete_snapshot(context, snapshot_id):
    #snapshot = ec2utils.get_db_item(context, snapshot_id)
    cinder = clients.cinder(context)
    try:
        cinder.backups.delete(snapshot_id)
    except cinder_exception.NotFound:
        pass
    os_snapshot=cinder.backups.get(snapshot_id)
    # NOTE(andrey-mp) Don't delete item from DB until it disappears from Cloud
    # It will be deleted by describer in the future
    return _format_snapshot_delete(context,os_snapshot)
    #return True


class SnapshotDescriber(common.TaggableItemsDescriber):

    KIND = 'snap'
    FILTER_MAP = {'description': 'description',
                  'snapshot-id': 'snapshotId',
                  'start-time': 'startTime',
                  'status': 'status',
                  'description': 'description',
                  'name': 'name',
                  'volume-id': 'volumeId',
                  'volume-size': 'volumeSize'}

    def format(self, snapshot, os_snapshot):
        return _format_snapshot(self.context, snapshot, os_snapshot,
                                self.volumes)

    def get_db_items(self):
        self.volumes = {vol['os_id']: vol
                        for vol in db_api.get_items(self.context, 'vol')}
        return super(SnapshotDescriber, self).get_db_items()

    def get_os_items(self):
        return clients.cinder(self.context).backups.list()

    def get_name(self, os_item):
        return ''


def describe_snapshots(context, snapshot_id=None):
    formatted_snapshots = SnapshotDescriber().describe(
        context)
    return {'snapshotSet': formatted_snapshots}

def _format_snapshot_delete(context, os_snapshot):
    status_map = {'new': 'pending',
                  'creating': 'creating',
                  'available': 'available',
                  'active': 'active',
                  'deleting': 'deleting',
                  'deleted': 'deleted',
                  'error': 'error'}
    mapped_status = status_map.get(os_snapshot.status, os_snapshot.status)
    return {'status':mapped_status}


def _format_snapshot(context, snapshot, os_snapshot, volumes={},
                     volume_id=None):
    # NOTE(mikal): this is just a set of strings in cinder. If they
    # implement an enum, then we should move this code to use it. The
    # valid ec2 statuses are "pending", "completed", and "error".
    status_map = {'new': 'pending',
                  'creating': 'creating',
                  'available': 'available',
                  'active': 'active',
                  'deleting': 'deleting',
                  'deleted': 'deleted',
                  'error': 'error'}

    mapped_status = status_map.get(os_snapshot.status, os_snapshot.status)
    if not mapped_status:
        return None

    #if not volume_id and os_snapshot.volume_id:
       # volume = ec2utils.get_db_item_by_os_id(
       #         context, 'vol', os_snapshot.volume_id, volumes
    volume_id = os_snapshot.volume_id

    # NOTE(andrey-mp): ownerId and progress are empty in just created snapshot
    #ownerId = os_snapshot.project_id
    #if not ownerId:
    #ownerId = context.project_id
    #progress = os_snapshot.progress
    #if not progress:
    #progress = '0%'
    return {'snapshotId': os_snapshot.id,
            'volumeId': volume_id,
            'status': mapped_status,
            'description': os_snapshot.description,
            'name': os_snapshot.name,
            'startTime': os_snapshot.created_at,
            'volumeSize': os_snapshot.size}
            #'ownerId': ownerId,
            #'description': os_snapshot.display_description}
