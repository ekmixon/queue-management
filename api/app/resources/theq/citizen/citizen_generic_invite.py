'''Copyright 2018 Province of British Columbia

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.'''

from filelock import FileLock
from flask import g, request
from flask_restx import Resource
from qsystem import api, api_call_with_retry, db, socketio, my_print, get_key
from app.models.theq import Citizen, CSR, CitizenState, Period, PeriodState, ServiceReq, SRState
from app.schemas.theq import CitizenSchema
from datetime import datetime
from pprint import pprint
from app.utilities.auth_util import Role, has_any_role
from app.auth.auth import jwt


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def csr_find_by_user():
    return CSR.find_by_username(g.jwt_oidc_token_info['username'])


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_active():
    return CitizenState.query.filter_by(cs_state_name='Active').first()


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_wait():
    return PeriodState.get_state_by_name("Waiting")


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_citizen(counter_id, active_citizen_state, csr, waiting_period_state):
    return (
        Citizen.query.filter_by(
            counter_id=counter_id,
            cs_id=active_citizen_state.cs_id,
            office_id=csr.office_id,
        )
        .join(Citizen.service_reqs)
        .join(ServiceReq.periods)
        .filter_by(ps_id=waiting_period_state.ps_id)
        .filter(Period.time_end.is_(None))
        .order_by(Citizen.priority, Citizen.start_time)
        .first()
    )


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_citizen2(active_citizen_state, csr, waiting_period_state):
    return (
        Citizen.query.filter_by(
            cs_id=active_citizen_state.cs_id, office_id=csr.office_id
        )
        .join(Citizen.service_reqs)
        .join(ServiceReq.periods)
        .filter_by(ps_id=waiting_period_state.ps_id)
        .filter(Period.time_end.is_(None))
        .order_by(Citizen.priority, Citizen.citizen_id)
        .first()
    )


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_active_sr(citizen):
    return citizen.get_active_service_request()


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def invite_active_sr(active_service_request,csr,citizen):
    active_service_request.invite(csr, invite_type="generic", sr_count=len(citizen.service_reqs))


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_active_ss():
    return SRState.get_state_by_name("Active")


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_active_sr(citizen):
    return citizen.get_active_service_request()


@jwt.has_one_of_roles([Role.internal_user.value])
@api_call_with_retry
def find_active_sr(citizen):
    return citizen.get_active_service_request()


@api.route("/citizens/invite/", methods=['POST'])
class CitizenGenericInvite(Resource):

    citizen_schema = CitizenSchema()
    citizens_schema = CitizenSchema(many=True)

    @jwt.has_one_of_roles([Role.internal_user.value])
    def post(self):
        #for x in range(0, 25):
        key = f"DR->{get_key()}"
        y = 0 + 1
        #print("DATETIME:", datetime.now(), "starting loop:", y, "==>Key : ", key)
        csr = csr_find_by_user()
        #print("DATETIME:", datetime.now(), "==>Key : ", key,"===>AFTER CALL TO csr_find_by_user:", csr)
        lock = FileLock(f"lock/invite_citizen_{csr.office_id}.lock")
        with lock:

            #active_citizen_state = find_active()
            active_citizen_state = citizen_state
            #print("DATETIME:", datetime.now(), "==>Key : ", key, "===>AFTER CALL TO find_Active:", active_citizen_state)

            waiting_period_state = find_wait()
            #print("DATETIME:", datetime.now(), "==>Key : ", key, "===>AFTER CALL TO find_wait:", waiting_period_state)
            citizen = None
            json_data = request.get_json()

            if json_data and 'counter_id' in json_data:
                counter_id = int(json_data.get('counter_id'))
            else:
                counter_id = int(csr.counter_id)

            citizen = find_citizen(counter_id,active_citizen_state, csr, waiting_period_state)

            # If no matching citizen with the same counter type, get next one
            if citizen is None:
                citizen = find_citizen2(active_citizen_state, csr, waiting_period_state)

            if citizen is None:
                return {"message": "There is no citizen to invite"}, 400

            my_print(
                f"==> POST /citizens/invite/ Citizen: {str(citizen.citizen_id)}, Ticket: {citizen.ticket_number}"
            )


            db.session.refresh(citizen)

            active_service_request = find_active_sr(citizen)
            #print("DATETIME:", datetime.now(), "==>Key : ", key, "===>AFTER CALL TO find_active_sr:", citizen)

            try:
                invite_active_sr(active_service_request,csr,citizen)
                #print("DATETIME:", datetime.now(), "==>Key : ", key, "===>AFTER CALL TO invite_active_sr:")

            except TypeError:
                return {"message": "Error inviting citizen. Please try again."}, 400


            active_service_state = find_active_ss()
            #print("DATETIME:", datetime.now(), "==>Key : ", key, "===>AFTER CALL TO find_active_ss:", active_service_state)
            active_service_request.sr_state_id = active_service_state.sr_state_id
            db.session.add(citizen)
            db.session.commit()

            socketio.emit('update_customer_list', {}, room=csr.office_id)
            socketio.emit('citizen_invited', {}, room=f'sb-{csr.office.office_number}')
            result = self.citizen_schema.dump(citizen)
            socketio.emit('update_active_citizen', result, room=csr.office_id)

                #print("DATETIME:", datetime.now(), "end loop:     ", y , "==>Key : ", key)

        return {'citizen': result,
                'errors': self.citizen_schema.validate(citizen)}, 200

try:
    citizen_state = CitizenState.query.filter_by(cs_state_name="Active").first()
    active_id = citizen_state.cs_id
except:
    active_id = 1
    print("==> In citizen_generic_invite.py")
    print("    --> NOTE!!  You should only see this if doing a 'python3 manage.py db upgrade'")
