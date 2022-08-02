import json
import logging
import urllib
from qsystem import application, my_print
from app.utilities.document_service import DocumentService
from datetime import datetime
import pytz
from dateutil import parser

class BCMPService:
    base_url = application.config['BCMP_BASE_URL']
    auth_token = application.config['BCMP_AUTH_TOKEN']

    def __init__(self):
        return
    
    def __exam_time_format(self, date_value):
        return date_value.strftime("%a %b %d, %Y at %-I:%M %p")

    def send_request(self, path, method, data):
        if method == 'POST':
            request_data = bytes(json.dumps(data), encoding="utf-8")
        else:
            request_data = None

        my_print("=== SENDING BCMP REQUEST ===")
        my_print(f"  ==> url: {path}")
        my_print(f"  ==> method: {method}")
        my_print(f"  ==> data: {request_data}")
        req = urllib.request.Request(path, data=request_data, method=method)
        req.add_header('Content-Type', 'application/json')
        my_print('request')
        my_print(req)

        response = urllib.request.urlopen(req)


        response_data = response.read().decode('utf8')
        my_print(response_data)

        try:
            return json.loads(response_data)
        except json.decoder.JSONDecodeError:
            logging.warning(
                f"Error decoding JSON response data. Response data: {response_data}"
            )

            return False

    def check_exam_status(self, exam):
        url = f"{self.base_url}/auth=env_exam;{self.auth_token}/JSON/status"
        data = {
            "jobs": [
                exam.bcmp_job_id
            ]
        }
        response = self.send_request(url, 'POST', data)

        if response and response['jobs']:
            for job in response['jobs']:
                my_print(job)
                if job['jobId'] == exam.bcmp_job_id:
                    return job

        return False

    def bulk_check_exam_status(self, exams):
        url = f"{self.base_url}/auth=env_exam;{self.auth_token}/JSON/status"
        data = {
            "jobs": []
        }

        for exam in exams:
            data["jobs"].append(exam.bcmp_job_id)

        response = self.send_request(url, 'POST', data)
        my_print(response)

        return response

    def create_individual_exam(self, exam, exam_fees, invigilator, pesticide_office, oidc_token_info):
        url = f"{self.base_url}/auth=env_exam;{self.auth_token}/JSON/create:ENV-IPM-EXAM"


        office_name = pesticide_office.office_name if pesticide_office else None
        receipt_number = f"{exam_fees} fees"
        if exam.receipt:
            receipt_number = exam.receipt

        exam_type_name = exam.exam_type.exam_type_name if exam.exam_type else None
        invigilator_name = invigilator.invigilator_name if invigilator else None
        bcmp_exam = {
            "EXAM_SESSION_LOCATION" : office_name,
            "REGISTRAR_name" : oidc_token_info['preferred_username'],
            "RECIPIENT_EMAIL_ADDRESS" : oidc_token_info['email'],
            "REGISTRAR_phoneNumber" : "",
            "students": [
                {
                    "REGISTRAR_name": invigilator_name,
                    "EXAM_CATEGORY": exam_type_name,
                    "STUDENT_LEGAL_NAME_first": exam.examinee_name,
                    "STUDENT_LEGAL_NAME_last": exam.examinee_name,
                    "STUDENT_emailAddress": exam.examinee_email,
                    "STUDENT_phoneNumber": exam.examinee_phone,
                    "REGISTRATION_NOTES": exam.notes,
                    "RECEIPT_RMS_NUMBER": receipt_number
                }
            ]
        }

        return self.send_request(url, 'POST', bcmp_exam)

    def create_group_exam_bcmp(self, exam, booking, candiate_list, invigilator, pesticide_office, oidc_token_info):
        url = f"{self.base_url}/auth=env_exam;{self.auth_token}/JSON/create:ENV-IPM-EXAM-GROUP"


        invigilator_name = invigilator.invigilator_name if invigilator else None
        office_name = None
        time_zone = pytz.timezone('America/Vancouver')
        if pesticide_office:
            office_name = pesticide_office.office_name
            time_zone = pytz.timezone(pesticide_office.timezone.timezone_name)

        my_print(exam.expiry_date.strftime("%a %b %d, %Y at %-I:%M %p"))
        exam_text = None
        if booking:
            exam_utc = parser.parse(booking["start_time"])
            exam_time = exam_utc.astimezone(tz=time_zone)
            exam_text = self.__exam_time_format(exam_time)

        bcmp_exam = {
            "EXAM_SESSION_LOCATION": office_name,
            "REGISTRAR_name" : oidc_token_info['preferred_username'],
            "RECIPIENT_EMAIL_ADDRESS" : oidc_token_info['email'],
            "REGISTRAR_phoneNumber": "",
            "students": []
        }

        if exam_text:
            bcmp_exam["SESSION_DATE_TIME"] = exam_text

        for candiate in candiate_list:
            bcmp_exam["students"].append({
                "EXAM_CATEGORY": candiate["exam_type"],
                "STUDENT_LEGAL_NAME_first": candiate["examinee_name"],
                "STUDENT_LEGAL_NAME_last": candiate["examinee_name"],
                "STUDENT_emailAddress": candiate["examinee_email"],
                "STUDENT_phoneNumber": "",
                "STUDENT_ADDRESS_line1": "",
                "STUDENT_ADDRESS_line2": "",
                "STUDENT_ADDRESS_city": "",
                "STUDENT_ADDRESS_province": "",
                "STUDENT_ADDRESS_postalCode": "",
                "REGISTRATION_NOTES": "",
                "RECEIPT_RMS_NUMBER": candiate["receipt"],
                "PAYMENT_METHOD": candiate["fees"],
                "FEE_PAYMENT_NOTES": ""
            })

        return self.send_request(url, 'POST', bcmp_exam)

    def create_group_exam(self, exam):
        url = f"{self.base_url}/auth=env_exam;{self.auth_token}/JSON/create:ENV-IPM-EXAM"


        bcmp_exam = {
            "students": []
        }

        for s in exam.students:
            bcmp_exam["students"].append({"name": s.name})

        return self.send_request(url, 'POST', bcmp_exam)

    def send_exam_to_bcmp(self, exam):
        url = f"{self.base_url}/auth=env_exam;{self.auth_token}/JSON/create:ENV-IPM-EXAM-API-ACTION"


        client = DocumentService(
            application.config["MINIO_HOST"],
            application.config["MINIO_BUCKET"],
            application.config["MINIO_ACCESS_KEY"],
            application.config["MINIO_SECRET_KEY"],
            application.config["MINIO_USE_SECURE"]
        )

        filename = f"{exam.exam_id}.pdf"

        presigned_url = client.get_presigned_get_url(filename)
        json_data = {
            "action": {
                "jobId": exam.bcmp_job_id,
                "actionName": "UPLOAD_RESPONSE_PDF",
                "remoteUrl": presigned_url
            }
        }

        return self.send_request(url, 'POST', json_data)

    def email_exam_invigilator(self, exam, invigilator_name, invigilator_email, invigilator_phone):
        url = f"{self.base_url}/auth=env_exam;{self.auth_token}/JSON/create:ENV-IPM-EXAM-API-ACTION"


        json_data = {
            "action": {
                "jobId": exam.bcmp_job_id,
                "actionName": "SEND_TO_INVIGILATOR",
                "invigilatorName": invigilator_name,
                "invigilatorEmailAddress": invigilator_email,
                "invigilatorPhoneNumber": invigilator_phone
            }
        }

        return self.send_request(url, "POST", json_data)
