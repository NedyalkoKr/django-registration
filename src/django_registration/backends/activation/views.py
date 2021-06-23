"""
A two-step (registration followed by activation) workflow, implemented
by emailing an HMAC-verified timestamped activation token to the user
on signup.

"""

import stripe
import djstripe
from django.contrib import messages
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.core import signing
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django_registration import signals
from django.contrib.auth.models import Group
from django_registration.exceptions import ActivationError
from django_registration.views import ActivationView as BaseActivationView
from django_registration.views import RegistrationView as BaseRegistrationView
from django.contrib.auth import get_user_model
User = get_user_model()

REGISTRATION_SALT = getattr(settings, "REGISTRATION_SALT", "registration")


class RegistrationView(BaseRegistrationView):
    """
    Register a new (inactive) user account, generate an activation key
    and email it to the user.

    This is different from the model-based activation workflow in that
    the activation key is the username, signed using Django's
    TimestampSigner, with HMAC verification on activation.

    """

    email_body_template = "django_registration/activation_email_body.txt"
    email_subject_template = "django_registration/activation_email_subject.txt"
    success_url = reverse_lazy("django_registration_complete")

    def register(self, form):
        new_user = self.create_inactive_user(form)
        signals.user_registered.send(
            sender=self.__class__, user=new_user, request=self.request
        )
        return new_user

    def create_inactive_user(self, form):
        """
        Create the inactive user account and send an email containing
        activation instructions.

        """
        new_user = form.save(commit=False)
        new_user.is_active = False
        new_user.save()

        self.send_activation_email(new_user)

        return new_user

    def get_activation_key(self, user):
        """
        Generate the activation key which will be emailed to the user.

        """
        return signing.dumps(obj=user.get_username(), salt=REGISTRATION_SALT)

    def get_email_context(self, activation_key):
        """
        Build the template context used for the activation email.

        """
        scheme = "https" if self.request.is_secure() else "http"
        return {
            "scheme": scheme,
            "activation_key": activation_key,
            "expiration_days": settings.ACCOUNT_ACTIVATION_DAYS,
            "site": get_current_site(self.request),
        }

    def send_activation_email(self, user):
        """
        Send the activation email. The activation key is the username,
        signed using TimestampSigner.

        """
        activation_key = self.get_activation_key(user)
        context = self.get_email_context(activation_key)
        context["user"] = user
        subject = render_to_string(
            template_name=self.email_subject_template,
            context=context,
            request=self.request,
        )
        # Force subject to a single line to avoid header-injection
        # issues.
        subject = "".join(subject.splitlines())
        message = render_to_string(
            template_name=self.email_body_template,
            context=context,
            request=self.request,
        )
        user.email_user(subject, message, settings.DEFAULT_FROM_EMAIL)


class ActivationView(BaseActivationView):
    """
    Given a valid activation key, activate the user's
    account. Otherwise, show an error message stating the account
    couldn't be activated.

    """

    ALREADY_ACTIVATED_MESSAGE = _(
        "The account you tried to activate has already been activated."
    )
    ACCOUNT_ALREADY_EXIST = ("It seems that you already have an account.")
    BAD_USERNAME_MESSAGE = _("The account you attempted to activate is invalid.")
    EXPIRED_MESSAGE = _("This account has expired.")
    INVALID_KEY_MESSAGE = _("The activation key you provided is invalid.")
    success_url = reverse_lazy("django_registration_activation_complete")

    def activate(self, request, *args, **kwargs):
        username = self.validate_key(kwargs.get("activation_key"))
        user = self.get_user(username)
        customers_group = Group.objects.get(name__iexact="customers")
        stripe.max_network_retries = 6

        if settings.DEBUG:
            stripe.api_key = settings.STRIPE_TEST_SECRET_KEY
            remote_ip = request.META.get('REMOTE_ADDR')
        else:
            stripe.api_key = settings.STRIPE_LIVE_SECRET_KEY
            remote_ip = request.META.get('X-Forwarded-For')[:14]

        # if User.objects.filter(user_ip=remote_ip).exists() or djstripe.models.Customer.objects.filter(email=user.email):
        #     user.delete()
        #     raise ActivationError(
        #         self.ACCOUNT_ALREADY_EXIST, code="account_exist"
        #     )
        if djstripe.models.Customer.objects.filter(email=user.email).exists():
            # user.delete()
            raise ActivationError(
                self.ACCOUNT_ALREADY_EXIST, code="account_exist"
            )
        else:
            customer = stripe.Customer.create(
                email=user.email,
            )
            subscription = stripe.Subscription.create(
                customer=customer.id,
                items=[
                    {
                        "price": settings.STRIPE_PRICE_ID,
                        "quantity": 1,
                    },
                ],
                trial_period_days=10,
                cancel_at_period_end=True,
                metadata={
                    "user_in_trial": True,
                },
            )
            user.groups.add(customers_group)
            user.is_customer = True
            user.user_ip = remote_ip
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS, 'account is activated.', 'account-activated')
        return user

    def validate_key(self, activation_key):
        """
        Verify that the activation key is valid and within the
        permitted activation time window, returning the username if
        valid or raising ``ActivationError`` if not.

        """
        try:
            username = signing.loads(
                activation_key,
                salt=REGISTRATION_SALT,
                max_age=settings.ACCOUNT_ACTIVATION_DAYS * 3600,
            )
            return username
        except signing.SignatureExpired:
            raise ActivationError(self.EXPIRED_MESSAGE, code="expired")
        except signing.BadSignature:
            raise ActivationError(
                self.INVALID_KEY_MESSAGE,
                code="invalid_key",
                params={"activation_key": activation_key},
            )

    def get_user(self, username):
        """
        Given the verified username, look up and return the
        corresponding user account if it exists, or raising
        ``ActivationError`` if it doesn't.

        """
        User = get_user_model()
        try:
            user = User.objects.get(**{User.USERNAME_FIELD: username})
            if user.is_active:
                raise ActivationError(
                    self.ALREADY_ACTIVATED_MESSAGE, code="already_activated"
                )
            return user
        except User.DoesNotExist:
            raise ActivationError(self.BAD_USERNAME_MESSAGE, code="bad_username")
