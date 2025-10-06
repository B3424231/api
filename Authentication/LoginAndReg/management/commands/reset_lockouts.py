from django.core.management.base import BaseCommand
from django.utils import timezone
from LoginAndReg.models import CustomUser

class Command(BaseCommand):
    help = 'Reset all user account lockouts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            help='Reset lockout for specific username',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Reset all user lockouts',
        )

    def handle(self, *args, **options):
        if options['username']:
            try:
                user = CustomUser.objects.get(username=options['username'])
                user.reset_failed_attempts()
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully reset lockout for user: {user.username}')
                )
            except CustomUser.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'User with username "{options["username"]}" does not exist')
                )
        elif options['all']:
            blocked_users = CustomUser.objects.filter(is_blocked=True)
            count = 0
            for user in blocked_users:
                user.reset_failed_attempts()
                count += 1
            self.stdout.write(
                self.style.SUCCESS(f'Successfully reset lockouts for {count} users')
            )
        else:
            self.stdout.write(
                self.style.ERROR('Please specify --username <username> or --all')
            )
