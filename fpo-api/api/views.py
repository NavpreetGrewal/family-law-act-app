"""
    REST API Documentation for Family Protection Order

    OpenAPI spec version: v1


    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

from datetime import datetime
from django.utils import timezone
from rest_framework import status
import logging
import json
import uuid
from django.http import Http404
from django.conf import settings
from api.models.PreparedPdf import PreparedPdf
import base64

from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound
from django.template.loader import get_template
from django.core.exceptions import PermissionDenied
from django.middleware.csrf import get_token
from api.serializers import ApplicationListSerializer
from api.efiling import upload_documents, generate_efiling_url

from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework import generics

from api.auth import (
    get_login_uri,
    get_logout_uri
)
from api.models.User import User
from api.models.Application import Application
from api.pdf import render as render_pdf

LOGGER = logging.getLogger(__name__)


class AcceptTermsView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        request.user.accepted_terms_at = datetime.now()
        request.user.save()
        return Response({'ok': True})


class UserStatusView(APIView):
    def get(self, request: Request):
        logged_in = isinstance(request.user, User)
        info = {
            "accepted_terms_at": logged_in and request.user.accepted_terms_at or None,
            "user_id": logged_in and request.user.authorization_id or None,
            "email": logged_in and request.user.email or None,
            "first_name": logged_in and request.user.first_name or None,
            "last_name": logged_in and request.user.last_name or None,
            "is_staff": logged_in and request.user.is_staff,
            "universal_id": logged_in and request.user.universal_id,
            "login_uri": get_login_uri(request),
            "logout_uri": get_logout_uri(request),
            "surveys": [],
        }
        if logged_in and request.auth == "demo":
            info["demo_user"] = True
        ret = Response(info)
        uid = request.META.get("HTTP_X_DEMO_LOGIN")
        if uid and logged_in:
            # remember demo user
            ret.set_cookie("x-demo-login", uid)
        elif request.COOKIES.get("x-demo-login") and not logged_in:
            # logout
            ret.delete_cookie("x-demo-login")
        ret.set_cookie("csrftoken", get_token(request))
        return ret


class SurveyPdfView(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def generate_pdf(self, name, data):
        template = '{}.html'.format(name)
        template = get_template(template)
        html_content = template.render(data)
        pdf_content = render_pdf(html_content)
        return pdf_content

    def get_pdf(self, pk):
        try:
            pdf_id = Application.objects.values_list("prepared_pdf_id", flat=True).get(pk=pk)
            pdf_result = PreparedPdf.objects.get(id=pdf_id)
            return pdf_result
        except (PreparedPdf.DoesNotExist, Application.DoesNotExist):
            LOGGER.debug("No record found")
            return

    def post(self, request, pk=1, new_pdf=None, name=None):
        data = request.data
        uid = request.user.id
        application = get_app_queryset(pk, uid)
        if not application:
            return HttpResponseNotFound("No record found")

        name = request.query_params.get("name")

        # FIXME Remove this line,(for testing only)
        new_pdf = False
        try:
            pdf_response = None
            pdf_result = self.get_pdf(pk)
            if pdf_result and not new_pdf:
                pdf_content = settings.ENCRYPTOR.decrypt(pdf_result.key_id, pdf_result.data)

            elif new_pdf and pdf_result:
                pdf_queryset = PreparedPdf.objects.filter(id=pdf_result.id)
                pdf_content = self.generate_pdf(name, data)
                (pdf_key_id, pdf_content_enc) = settings.ENCRYPTOR.encrypt(pdf_content)
                pdf_queryset.update(data=pdf_content_enc)

            else:
                pdf_content = self.generate_pdf(name, data)
                (pdf_key_id, pdf_content_enc) = settings.ENCRYPTOR.encrypt(pdf_content)
                pdf_response = PreparedPdf(data=pdf_content_enc, key_id=pdf_key_id)
                pdf_response.save()
                application.update(prepared_pdf_id=pdf_response.pk)
            application.update(last_printed=timezone.now())
        except Exception as ex:
            LOGGER.error("ERROR: Pdf generation failed %s", ex)
            raise

        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="report.pdf"'

        response.write(pdf_content)

        return response


class ApplicationListView(generics.ListAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    """
    List all application for a user
    """
    def get_app_list(self, id):
        try:
            return Application.objects.filter(user_id=id)
        except Application.DoesNotExist:
            raise Http404

    def get(self, request, format=None):
        user_id = request.user.id
        if user_id:
            applications = self.get_app_list(request.user.id)
            serializer = ApplicationListSerializer(applications, many=True)
            return Response(serializer.data)
        return HttpResponseForbidden("User id not provided")


class ApplicationView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get_app_object(self, pk, uid):
        try:
            return Application.objects.get(pk=pk, user_id=uid)
        except Application.DoesNotExist:
            raise Http404

    def encrypt_steps(self, steps):
        try:
            steps_bin = json.dumps(steps).encode("ascii")
            (steps_key_id, steps_enc) = settings.ENCRYPTOR.encrypt(steps_bin)
            return (steps_key_id, steps_enc)
        except Exception as ex:
            LOGGER.error("ERROR! %s", ex)

    def get(self, request, pk, format=None):
        uid = request.user.id
        application = self.get_app_object(pk, uid)
        steps_dec = settings.ENCRYPTOR.decrypt(application.key_id, application.steps)
        steps = json.loads(steps_dec)
        data = {"id": application.id,
                "type": application.app_type,
                "steps": steps,
                "lastUpdate": application.last_updated,
                "currentStep": application.current_step,
                "allCompleted": application.all_completed,
                "userType": application.user_type,
                "userName": application.user_name,
                "userId": application.user_id,
                "applicantName": application.applicant_name,
                "respondentName": application.respondent_name}
        return Response(data)

    def post(self, request: Request):
        uid = request.user.id
        if not uid:
            return HttpResponseForbidden("Missing user ID")

        body = request.data
        if not body:
            return HttpResponseBadRequest("Missing request body")

        (steps_key_id, steps_enc) = self.encrypt_steps(body["steps"])

        db_app = Application(
            last_updated=timezone.now(),
            app_type=body.get("type"),
            current_step=body.get("currentStep"),
            all_completed=body.get("allCompleted"),
            steps=steps_enc,
            user_type=body.get("userType"),
            applicant_name=body.get("applicantName"),
            user_name=body.get("userName"),
            key_id=steps_key_id,
            respondent_name=body.get("respondentName"),
            user_id=uid)

        db_app.save()
        return Response({"app_id": db_app.pk})

    def put(self, request, pk, format=None):
        uid = request.user.id
        body = request.data
        if not body:
            return HttpResponseBadRequest("Missing request body")

        application_queryset = get_app_queryset(pk, uid)
        if not application_queryset:
            return HttpResponseNotFound("No record found")

        (steps_key_id, steps_enc) = self.encrypt_steps(body["steps"])

        application_queryset.update(last_updated=timezone.now())
        application_queryset.update(app_type=body.get("type"))
        application_queryset.update(current_step=body.get("currentStep"))
        application_queryset.update(steps=steps_enc)
        application_queryset.update(user_type=body.get("userType"))
        application_queryset.update(applicant_name=body.get("applicantName"))
        application_queryset.update(user_name=body.get("userName"))
        application_queryset.update(respondent_name=body.get("respondentName"))
        return Response("success")

    def delete(self, request, pk, format=None):
        uid = request.user.id
        application = self.get_app_object(pk, uid)
        application.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


def get_app_queryset(pk, uid):
    try:
        return Application.objects.filter(user_id=uid).filter(pk=pk)
    except Application.DoesNotExist:
        raise Http404


class UploadDocumentView(APIView):

    def post(self, request):
        docs = request.FILES.getlist('files')
        submissionId = None
        files = []
        if docs:
            for doc in docs:
                files.append(('files', (doc.name, doc.read())))

        uid = request.user.id
        transaction_id = get_transaction(request)
        print("tras", transaction_id)
        user_id = get_universal_id(uid)
        if not user_id:
            raise PermissionDenied()

        try:
            upload_res = upload_documents(files, user_id, transaction_id)
            if upload_res:
                submissionId = upload_res["submissionId"]
        except Exception as exception:
            LOGGER.exception("Error! %s", exception)
            raise
        return Response({"submissionId": submissionId})


class GenerateUrlView(APIView):

    def post(self, request, submissionId=None):
        data = request.data
        submission_id = request.query_params.get("submissionId")
        print("sub", submission_id)
        if not data:
            return HttpResponseBadRequest("Missing request body")
        uid = request.user.id
        if not uid:
            return HttpResponseForbidden("Missing user ID")
        efiling_url = None
        transaction_id = get_transaction(request)
        print("transactionId", transaction_id)
        
        user_id = get_universal_id(uid)
        print("user_id", user_id)
        if not user_id:
            raise PermissionDenied()

        try:
            efiling_url_res = generate_efiling_url(data, user_id, transaction_id, submission_id)
            if efiling_url_res:
                efiling_url = efiling_url_res["efilingUrl"]
                LOGGER.debug("Redirect response %s", efiling_url_res)
        except Exception as exception:
            LOGGER.exception("Error! %s", exception)
            raise
        return Response({"efilingUrl": efiling_url})
    

def get_transaction(request):
    """
    Get the current transaction id stored in session, otherwise generate one.
    """
    guid = request.session.get('transaction_id', None)
    if not guid:
        guid = str(uuid.uuid4())
        request.session['transaction_id'] = guid
    return guid


def get_universal_id(uid):
    try:
        return User.objects.values_list("universal_id", flat=True).get(pk=uid)     
    except User.DoesNotExist:
        LOGGER.debug("No record found")
        return
