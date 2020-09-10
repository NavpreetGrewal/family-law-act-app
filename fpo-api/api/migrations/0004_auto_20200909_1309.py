# Generated by Django 2.1.15 on 2020-09-09 20:09

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_surveyresult'),
    ]

    operations = [
        migrations.CreateModel(
            name='Application',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('app_type', models.CharField(blank=True, default='', max_length=100)),
                ('last_updated', models.DateTimeField(blank=True, null=True)),
                ('current_step', models.IntegerField(blank=True, null=True)),
                ('all_completed', models.BooleanField(blank=True, default=False)),
                ('last_printed', models.DateTimeField(blank=True, null=True)),
                ('user_type', models.CharField(blank=True, default='', max_length=100)),
                ('user_name', models.CharField(blank=True, default='', max_length=100)),
                ('application_name', models.CharField(blank=True, default='', max_length=100)),
                ('respondent_name', models.CharField(blank=True, default='', max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Page',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(blank=True, default='', max_length=100)),
                ('label', models.CharField(blank=True, default='', max_length=100)),
                ('progress', models.IntegerField(blank=True, null=True)),
                ('active', models.BooleanField(blank=True, default=False)),
                ('clickable', models.BooleanField(blank=True, default=False)),
            ],
        ),
        migrations.CreateModel(
            name='PreparedPdf',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('data', models.BinaryField(blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Step',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('step_type', models.CharField(blank=True, default='', max_length=100)),
                ('label', models.CharField(blank=True, default='', max_length=100)),
                ('icon', models.CharField(blank=True, default='', max_length=100)),
                ('result', jsonfield.fields.JSONField(blank=True, null=True)),
                ('metadata', jsonfield.fields.JSONField(blank=True, null=True)),
                ('current_page', models.IntegerField(blank=True, null=True)),
                ('active', models.BooleanField(blank=True, default=False)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('application', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='application_id', to='api.Application')),
            ],
        ),
        migrations.AlterField(
            model_name='user',
            name='last_name',
            field=models.CharField(blank=True, max_length=150, verbose_name='last name'),
        ),
        migrations.AddField(
            model_name='page',
            name='step',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='step_id', to='api.Step'),
        ),
        migrations.AddField(
            model_name='application',
            name='prepared_pdf',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pdf_data', to='api.PreparedPdf'),
        ),
        migrations.AddField(
            model_name='application',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='app_user_Id', to=settings.AUTH_USER_MODEL),
        ),
    ]