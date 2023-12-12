# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import typing
from unittest import mock

import httpretty
import urllib3
import urllib3.exceptions

from opentelemetry import context, trace

# FIXME: fix the importing of this private attribute when the location of the _SUPPRESS_HTTP_INSTRUMENTATION_KEY is defined.
from opentelemetry.context import _SUPPRESS_HTTP_INSTRUMENTATION_KEY
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor
from opentelemetry.instrumentation.utils import _SUPPRESS_INSTRUMENTATION_KEY
from opentelemetry.propagate import get_global_textmap, set_global_textmap
from opentelemetry.semconv.trace import SpanAttributes
from opentelemetry.test.mock_textmap import MockTextMapPropagator
from opentelemetry.test.test_base import TestBase
from opentelemetry.util.http import get_excluded_urls

# pylint: disable=too-many-public-methods


class TestURLLib3Instrumentor(TestBase):
    HTTP_URL = "http://mock/status/200"
    HTTPS_URL = "https://mock/status/200"

    def setUp(self):
        super().setUp()

        self.env_patch = mock.patch.dict(
            "os.environ",
            {
                "OTEL_PYTHON_URLLIB3_EXCLUDED_URLS": "http://localhost/env_excluded_arg/123,env_excluded_noarg"
            },
        )
        self.env_patch.start()

        self.exclude_patch = mock.patch(
            "opentelemetry.instrumentation.urllib3._excluded_urls_from_env",
            get_excluded_urls("URLLIB3"),
        )
        self.exclude_patch.start()

        URLLib3Instrumentor().instrument()

        httpretty.enable(allow_net_connect=False)
        httpretty.register_uri(httpretty.GET, self.HTTP_URL, body="Hello!")
        httpretty.register_uri(httpretty.GET, self.HTTPS_URL, body="Hello!")
        httpretty.register_uri(httpretty.POST, self.HTTP_URL, body="Hello!")

    def tearDown(self):
        super().tearDown()
        URLLib3Instrumentor().uninstrument()

        httpretty.disable()
        httpretty.reset()

    def assert_span(self, exporter=None, num_spans=1):
        if exporter is None:
            exporter = self.memory_exporter
        span_list = exporter.get_finished_spans()
        self.assertEqual(num_spans, len(span_list))
        if num_spans == 0:
            return None
        if num_spans == 1:
            return span_list[0]
        return span_list

    def assert_success_span(
        self, response: urllib3.response.HTTPResponse, url: str
    ):
        self.assertEqual(b"Hello!", response.data)

        span = self.assert_span()
        self.assertIs(trace.SpanKind.CLIENT, span.kind)
        self.assertEqual("GET", span.name)

        attributes = {
            SpanAttributes.HTTP_METHOD: "GET",
            SpanAttributes.HTTP_URL: url,
            SpanAttributes.HTTP_STATUS_CODE: 200,
        }
        self.assertEqual(attributes, span.attributes)

    def assert_exception_span(self, url: str):
        span = self.assert_span()

        attributes = {
            SpanAttributes.HTTP_METHOD: "GET",
            SpanAttributes.HTTP_URL: url,
        }
        self.assertEqual(attributes, span.attributes)
        self.assertEqual(
            trace.status.StatusCode.ERROR, span.status.status_code
        )

    @staticmethod
    def perform_request(
        url: str, headers: typing.Mapping = None, retries: urllib3.Retry = None
    ) -> urllib3.response.HTTPResponse:
        if retries is None:
            retries = urllib3.Retry.from_int(0)

        pool = urllib3.PoolManager()
        return pool.request("GET", url, headers=headers, retries=retries)

    def test_basic_http_success(self):
        response = self.perform_request(self.HTTP_URL)
        self.assert_success_span(response, self.HTTP_URL)

    def test_basic_http_success_using_connection_pool(self):
        pool = urllib3.HTTPConnectionPool("mock")
        response = pool.request("GET", "/status/200")

        self.assert_success_span(response, self.HTTP_URL)

    def test_basic_https_success(self):
        response = self.perform_request(self.HTTPS_URL)
        self.assert_success_span(response, self.HTTPS_URL)

    def test_basic_https_success_using_connection_pool(self):
        pool = urllib3.HTTPSConnectionPool("mock")
        response = pool.request("GET", "/status/200")

        self.assert_success_span(response, self.HTTPS_URL)

    def test_schema_url(self):
        pool = urllib3.HTTPSConnectionPool("mock")
        response = pool.request("GET", "/status/200")

        self.assertEqual(b"Hello!", response.data)
        span = self.assert_span()
        self.assertEqual(
            span.instrumentation_info.schema_url,
            "https://opentelemetry.io/schemas/1.11.0",
        )

    def test_basic_not_found(self):
        url_404 = "http://mock/status/404"
        httpretty.register_uri(httpretty.GET, url_404, status=404)

        response = self.perform_request(url_404)
        self.assertEqual(404, response.status)

        span = self.assert_span()
        self.assertEqual(
            404, span.attributes.get(SpanAttributes.HTTP_STATUS_CODE)
        )
        self.assertIs(trace.status.StatusCode.ERROR, span.status.status_code)

    def test_basic_http_non_default_port(self):
        url = "http://mock:666/status/200"
        httpretty.register_uri(httpretty.GET, url, body="Hello!")

        response = self.perform_request(url)
        self.assert_success_span(response, url)

    def test_basic_http_absolute_url(self):
        url = "http://mock:666/status/200"
        httpretty.register_uri(httpretty.GET, url, body="Hello!")
        pool = urllib3.HTTPConnectionPool("mock", port=666)
        response = pool.request("GET", url)

        self.assert_success_span(response, url)

    def test_url_open_explicit_arg_parameters(self):
        url = "http://mock:666/status/200"
        httpretty.register_uri(httpretty.GET, url, body="Hello!")
        pool = urllib3.HTTPConnectionPool("mock", port=666)
        response = pool.urlopen(method="GET", url="/status/200")

        self.assert_success_span(response, url)

    def test_excluded_urls_explicit(self):
        url_201 = "http://mock/status/201"
        httpretty.register_uri(
            httpretty.GET,
            url_201,
            status=201,
        )

        URLLib3Instrumentor().uninstrument()
        URLLib3Instrumentor().instrument(excluded_urls=".*/201")
        self.perform_request(self.HTTP_URL)
        self.perform_request(url_201)

        self.assert_span(num_spans=1)

    def test_excluded_urls_from_env(self):
        url = "http://localhost/env_excluded_arg/123"
        httpretty.register_uri(
            httpretty.GET,
            url,
            status=200,
        )

        URLLib3Instrumentor().uninstrument()
        URLLib3Instrumentor().instrument()
        self.perform_request(self.HTTP_URL)
        self.perform_request(url)

        self.assert_span(num_spans=1)

    def test_uninstrument(self):
        URLLib3Instrumentor().uninstrument()

        response = self.perform_request(self.HTTP_URL)
        self.assertEqual(b"Hello!", response.data)
        self.assert_span(num_spans=0)
        # instrument again to avoid warning message on tearDown
        URLLib3Instrumentor().instrument()

    def test_suppress_instrumentation(self):
        suppression_keys = (
            _SUPPRESS_HTTP_INSTRUMENTATION_KEY,
            _SUPPRESS_INSTRUMENTATION_KEY,
        )
        for key in suppression_keys:
            self.memory_exporter.clear()

            with self.subTest(key=key):
                token = context.attach(context.set_value(key, True))
                try:
                    response = self.perform_request(self.HTTP_URL)
                    self.assertEqual(b"Hello!", response.data)
                finally:
                    context.detach(token)

                self.assert_span(num_spans=0)

    def test_context_propagation(self):
        previous_propagator = get_global_textmap()
        try:
            set_global_textmap(MockTextMapPropagator())
            response = self.perform_request(self.HTTP_URL)
            self.assertEqual(b"Hello!", response.data)

            span = self.assert_span()
            headers = dict(httpretty.last_request().headers)

            self.assertIn(MockTextMapPropagator.TRACE_ID_KEY, headers)
            self.assertEqual(
                headers[MockTextMapPropagator.TRACE_ID_KEY],
                str(span.get_span_context().trace_id),
            )
            self.assertIn(MockTextMapPropagator.SPAN_ID_KEY, headers)
            self.assertEqual(
                headers[MockTextMapPropagator.SPAN_ID_KEY],
                str(span.get_span_context().span_id),
            )
        finally:
            set_global_textmap(previous_propagator)

    def test_custom_tracer_provider(self):
        tracer_provider, exporter = self.create_tracer_provider()
        tracer_provider = mock.Mock(wraps=tracer_provider)

        URLLib3Instrumentor().uninstrument()
        URLLib3Instrumentor().instrument(tracer_provider=tracer_provider)

        response = self.perform_request(self.HTTP_URL)
        self.assertEqual(b"Hello!", response.data)

        self.assert_span(exporter=exporter)
        self.assertEqual(1, tracer_provider.get_tracer.call_count)

    @mock.patch(
        "urllib3.connectionpool.HTTPConnectionPool._make_request",
        side_effect=urllib3.exceptions.ConnectTimeoutError,
    )
    def test_request_exception(self, _):
        with self.assertRaises(urllib3.exceptions.ConnectTimeoutError):
            self.perform_request(
                self.HTTP_URL, retries=urllib3.Retry(connect=False)
            )

        self.assert_exception_span(self.HTTP_URL)

    @mock.patch(
        "urllib3.connectionpool.HTTPConnectionPool._make_request",
        side_effect=urllib3.exceptions.ProtocolError,
    )
    def test_retries_do_not_create_spans(self, _):
        with self.assertRaises(urllib3.exceptions.MaxRetryError):
            self.perform_request(self.HTTP_URL, retries=urllib3.Retry(1))

        # expect only a single span (retries are ignored)
        self.assert_exception_span(self.HTTP_URL)

    def test_url_filter(self):
        def url_filter(url):
            return url.split("?")[0]

        URLLib3Instrumentor().uninstrument()
        URLLib3Instrumentor().instrument(url_filter=url_filter)

        response = self.perform_request(self.HTTP_URL + "?e=mcc")
        self.assert_success_span(response, self.HTTP_URL)

    def test_credential_removal(self):
        url = "http://username:password@mock/status/200"

        response = self.perform_request(url)
        self.assert_success_span(response, self.HTTP_URL)

    def test_hooks(self):
        def request_hook(span, request, body, headers):
            span.update_name("name set from hook")

        def response_hook(span, request, response):
            span.set_attribute("response_hook_attr", "value")

        URLLib3Instrumentor().uninstrument()
        URLLib3Instrumentor().instrument(
            request_hook=request_hook, response_hook=response_hook
        )
        response = self.perform_request(self.HTTP_URL)
        self.assertEqual(b"Hello!", response.data)

        span = self.assert_span()

        self.assertEqual(span.name, "name set from hook")
        self.assertIn("response_hook_attr", span.attributes)
        self.assertEqual(span.attributes["response_hook_attr"], "value")

    def test_request_hook_params(self):
        def request_hook(span, request, headers, body):
            span.set_attribute(
                "request_hook_headers", json.dumps(dict(headers))
            )
            span.set_attribute("request_hook_body", body)

        URLLib3Instrumentor().uninstrument()
        URLLib3Instrumentor().instrument(
            request_hook=request_hook,
        )

        headers = {"header1": "value1", "header2": "value2"}
        body = "param1=1&param2=2"

        pool = urllib3.HTTPConnectionPool("mock")
        response = pool.request(
            "POST", "/status/200", body=body, headers=headers
        )

        self.assertEqual(b"Hello!", response.data)

        span = self.assert_span()

        self.assertIn("request_hook_headers", span.attributes)
        self.assertEqual(
            span.attributes["request_hook_headers"], json.dumps(headers)
        )
        self.assertIn("request_hook_body", span.attributes)
        self.assertEqual(span.attributes["request_hook_body"], body)

    def test_request_positional_body(self):
        def request_hook(span, request, headers, body):
            span.set_attribute("request_hook_body", body)

        URLLib3Instrumentor().uninstrument()
        URLLib3Instrumentor().instrument(
            request_hook=request_hook,
        )

        body = "param1=1&param2=2"

        pool = urllib3.HTTPConnectionPool("mock")
        response = pool.urlopen("POST", "/status/200", body)

        self.assertEqual(b"Hello!", response.data)

        span = self.assert_span()

        self.assertIn("request_hook_body", span.attributes)
        self.assertEqual(span.attributes["request_hook_body"], body)

    def test_no_op_tracer_provider(self):
        URLLib3Instrumentor().uninstrument()
        tracer_provider = trace.NoOpTracerProvider()
        URLLib3Instrumentor().instrument(tracer_provider=tracer_provider)

        response = self.perform_request(self.HTTP_URL)
        self.assertEqual(b"Hello!", response.data)
        self.assert_span(num_spans=0)
