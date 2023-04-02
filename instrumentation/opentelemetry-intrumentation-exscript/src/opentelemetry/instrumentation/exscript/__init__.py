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

"""
This library allows tracing HTTP requests made by the
`requests <https://requests.readthedocs.io/en/master/>`_ library.

Usage
-----

.. code-block:: python

    import requests
    from opentelemetry.instrumentation.requests import RequestsInstrumentor

    # You can optionally pass a custom TracerProvider to instrument().
    RequestsInstrumentor().instrument()
    response = requests.get(url="https://www.example.org/")

Configuration
-------------

Exclude lists
*************
To exclude certain URLs from being tracked, set the environment variable ``OTEL_PYTHON_REQUESTS_EXCLUDED_URLS``
(or ``OTEL_PYTHON_EXCLUDED_URLS`` as fallback) with comma delimited regexes representing which URLs to exclude.

For example,

::

    export OTEL_PYTHON_REQUESTS_EXCLUDED_URLS="client/.*/info,healthcheck"

will exclude requests such as ``https://site/client/123/info`` and ``https://site/xyz/healthcheck``.

API
---
"""

import functools
import types
from timeit import default_timer
from typing import Callable, Collection, Optional

from Exscript.protocols import Protocol

from opentelemetry.trace import set_span_in_context

from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.exscript.package import _instruments
from opentelemetry.instrumentation.exscript.version import __version__

from opentelemetry.metrics import Histogram, get_meter
from opentelemetry.propagate import inject
from opentelemetry.semconv.metrics import MetricInstruments
from opentelemetry.semconv.trace import SpanAttributes
from opentelemetry.trace import SpanKind, Tracer, get_tracer
from opentelemetry.trace.span import Span
from opentelemetry.trace.status import Status

_RequestHookT = Optional[Callable[[Span, Protocol], None]]
_ResponseHookT = Optional[Callable[[Span, Protocol], None]]


# pylint: disable=unused-argument
# pylint: disable=R0915
def _instrument(
    tracer: Tracer,
    duration_histogram: Histogram,
    request_hook: _RequestHookT = None,
    response_hook: _ResponseHookT = None,
):
    """Enables tracing of all requests calls that go through
    :code:`requests.session.Session.request` (this includes
    :code:`requests.get`, etc.)."""

    # Since
    # https://github.com/psf/requests/commit/d72d1162142d1bf8b1b5711c664fbbd674f349d1
    # (v0.7.0, Oct 23, 2011), get, post, etc are implemented via request which
    # again, is implemented via Session.request (`Session` was named `session`
    # before v1.0.0, Dec 17, 2012, see
    # https://github.com/psf/requests/commit/4e5c4a6ab7bb0195dececdd19bb8505b872fe120)

    wrapped_connect = Protocol.connect
    wrapped_login = Protocol.login
    wrapped_close = Protocol.close
    wrapped_send = Protocol.send
    wrapped_execute = Protocol.execute

    # connect(self, hostname=None, port=None):
    @functools.wraps(wrapped_connect)
    def instrumented_connect(self, hostname=None, port=None):
        protocol_name = self.__class__.__name__
        span_name = get_default_span_name(protocol_name, "connect")

        span_attributes = {
            "protocol.type": protocol_name,
        }
        span_attributes.update(get_protocol_attributes(self))
        if hostname:
            span_attributes["protocol.host"] = hostname
        if port:
            span_attributes["protocol.port"] = hostname

        metric_labels = {
            "protocol.type": protocol_name,
        }

        span = tracer.start_span(span_name, kind=SpanKind.CLIENT, attributes=span_attributes)

        exception = None
        if callable(request_hook):
            request_hook(span, self)

        start_time = default_timer()

        try:
            result = wrapped_connect(self, hostname=hostname, port=port)  # *** PROCEED
        except Exception as exc:  # pylint: disable=W0703
            exception = exc
            result = getattr(exc, "response", None)
        finally:
            elapsed_time = max(
                round((default_timer() - start_time) * 1000), 0
            )

        if callable(response_hook):
            response_hook(span, self, result)

        duration_histogram.record(elapsed_time, attributes=metric_labels)

        if exception is not None:
            raise exception.with_traceback(exception.__traceback__)
        
        self.opentelemetry_instrumentation_exscript_connect_span = span

        return result

    #login(self, account=None, app_account=None, flush=True):
    @functools.wraps(wrapped_login)
    def instrumented_login(self, account=None, app_account=None, flush=True):
        context = set_span_in_context(get_parent_span(self))
        protocol_name = self.__class__.__name__
        span_name = get_default_span_name(protocol_name, "login")

        span_attributes = {
            "protocol.type": protocol_name,
            "protocol.username": account.get_name(),
        }
        span_attributes.update(get_protocol_attributes(self))

        metric_labels = {
            "protocol.type": protocol_name,
        }

        span_kwargs = {
            "kind": SpanKind.CLIENT,
            "attributes": span_attributes
        }
        if context:
            span_kwargs["context"] = context

        with tracer.start_as_current_span(span_name, **span_kwargs) as span:
            exception = None
            if callable(request_hook):
                request_hook(span, self)

            start_time = default_timer()

            try:
                result = wrapped_login(
                    self, 
                    account=account, 
                    app_account=app_account, 
                    flush=flush
                )  # *** PROCEED
            except Exception as exc:  # pylint: disable=W0703
                exception = exc
                result = getattr(exc, "response", None)
            finally:
                elapsed_time = max(
                    round((default_timer() - start_time) * 1000), 0
                )

            if callable(response_hook):
                response_hook(span, self, result)

            duration_histogram.record(elapsed_time, attributes=metric_labels)

            if exception is not None:
                raise exception.with_traceback(exception.__traceback__)

        return result
    

    #close(self, force=False):
    @functools.wraps(wrapped_close)
    def instrumented_close(self, force=False):
        context = set_span_in_context(get_parent_span(self))
        protocol_name = self.__class__.__name__
        span_name = get_default_span_name(protocol_name, "close")

        span_attributes = {
            "protocol.type": protocol_name,
            "protocol.force_close": force,
        }
        span_attributes.update(get_protocol_attributes(self))

        metric_labels = {
            "protocol.type": protocol_name,
        }

        span_kwargs = {
            "kind": SpanKind.CLIENT,
            "attributes": span_attributes
        }
        if context:
            span_kwargs["context"] = context

        with tracer.start_as_current_span(span_name, **span_kwargs) as span:
            exception = None
            if callable(request_hook):
                request_hook(span, self)

            start_time = default_timer()

            try:
                result = wrapped_close(self, force=force)  # *** PROCEED
            except Exception as exc:  # pylint: disable=W0703
                exception = exc
                result = getattr(exc, "response", None)
            finally:
                elapsed_time = max(
                    round((default_timer() - start_time) * 1000), 0
                )

            if callable(response_hook):
                response_hook(span, self, result)

            duration_histogram.record(elapsed_time, attributes=metric_labels)

            if exception is not None:
                raise exception.with_traceback(exception.__traceback__)
            
        parent_span = get_parent_span(self)
        try:
            parent_span.end()
        except:
            pass

        return result
        

    # pylint: disable-msg=too-many-locals,too-many-branches
    @functools.wraps(wrapped_send)
    def instrumented_send(self, command):
        context = set_span_in_context(get_parent_span(self))
        protocol_name = self.__class__.__name__
        span_name = get_default_span_name(protocol_name, "send")

        span_attributes = {
            "protocol.type": protocol_name,
            "protocol.command": command,
        }
        span_attributes.update(get_protocol_attributes(self))

        metric_labels = {
            "protocol.type": protocol_name,
        }

        span_kwargs = {
            "kind": SpanKind.CLIENT,
            "attributes": span_attributes
        }
        if context:
            span_kwargs["context"] = context

        with tracer.start_as_current_span(span_name, **span_kwargs) as span:
            exception = None
            if callable(request_hook):
                request_hook(span, self)

            start_time = default_timer()

            try:
                result = wrapped_send(self, command)  # *** PROCEED
            except Exception as exc:  # pylint: disable=W0703
                exception = exc
                result = getattr(exc, "response", None)
            finally:
                elapsed_time = max(
                    round((default_timer() - start_time) * 1000), 0
                )

            if callable(response_hook):
                response_hook(span, self, result)

            duration_histogram.record(elapsed_time, attributes=metric_labels)

            if exception is not None:
                raise exception.with_traceback(exception.__traceback__)

        return result
    

    @functools.wraps(wrapped_execute)
    def instrumented_execute(self, command, consume=True):
        context = set_span_in_context(get_parent_span(self))
        protocol_name = self.__class__.__name__
        span_name = get_default_span_name(protocol_name, "execute")

        span_attributes = {
            "protocol.type": protocol_name,
            "protocol.command": command,
        }
        span_attributes.update(get_protocol_attributes(self))

        metric_labels = {
            "protocol.type": protocol_name,
        }

        span_kwargs = {
            "kind": SpanKind.CLIENT,
            "attributes": span_attributes
        }
        if context:
            span_kwargs["context"] = context

        with tracer.start_as_current_span(span_name, **span_kwargs) as span:
            exception = None
            if callable(request_hook):
                request_hook(span, self)

            start_time = default_timer()

            try:
                result = wrapped_execute(self, command, consume=consume)  # *** PROCEED
            except Exception as exc:  # pylint: disable=W0703
                exception = exc
                result = getattr(exc, "response", None)
            finally:
                elapsed_time = max(
                    round((default_timer() - start_time) * 1000), 0
                )

            span.set_attribute(
                "protocol.response", str(result)
            )

            if callable(response_hook):
                response_hook(span, self, result)

            duration_histogram.record(elapsed_time, attributes=metric_labels)

            if exception is not None:
                raise exception.with_traceback(exception.__traceback__)
            
        return result


    instrumented_connect.opentelemetry_instrumentation_exscript_applied = True
    instrumented_login.opentelemetry_instrumentation_exscript_applied = True
    instrumented_close.opentelemetry_instrumentation_exscript_applied = True
    instrumented_send.opentelemetry_instrumentation_exscript_applied = True
    instrumented_execute.opentelemetry_instrumentation_exscript_applied = True
    Protocol.connect = instrumented_connect
    Protocol.login = instrumented_login
    Protocol.close = instrumented_close
    Protocol.send = instrumented_send
    Protocol.execute = instrumented_execute



def _uninstrument():
    """Disables instrumentation of :code:`requests` through this module.

    Note that this only works if no other module also patches requests."""
    _uninstrument_from(Protocol)


def _uninstrument_from(instr_root, restore_as_bound_func=False):
    for instr_func_name in ("login", "close", "send", "execute"):
        instr_func = getattr(instr_root, instr_func_name)
        if not getattr(
            instr_func,
            "opentelemetry_instrumentation_exscript_applied",
            False,
        ):
            continue

        original = instr_func.__wrapped__  # pylint:disable=no-member
        if restore_as_bound_func:
            original = types.MethodType(original, instr_root)
        setattr(instr_root, instr_func_name, original)


def get_default_span_name(protocol_name, action):
    """Default implementation for name_callback, returns Exscript {protocol}."""
    return f"{protocol_name.strip()} {action.strip()}"


def get_parent_span(self):
    return getattr(
        self, 
        "opentelemetry_instrumentation_exscript_connect_span",
        None
    )


def get_protocol_attributes(self):
    return {
        "protocol.type": self.__class__.__name__,
        "protocol.timeout": self.get_timeout(),
        "protocol.connect_timeout": self.get_connect_timeout(),
        "protocol.host": self.host,
        "protocol.port": self.port,
        "protocol.os": self.guess_os(),
        "protocol.encoding": self.encoding,
        "protocol.prompt": getattr(self.get_prompt(), "pattern", self.get_prompt()),
        "protocol.error_prompt": getattr(self.get_error_prompt(), "pattern", self.get_error_prompt()),
        "protocol.protocol_authenticated": self.is_protocol_authenticated(),
        "protocol.app_authenticated": self.is_app_authenticated(),
        "protocol.app_authorized": self.is_app_authorized(),
    }


class ExscriptInstrumentor(BaseInstrumentor):
    """An instrumentor for requests
    See `BaseInstrumentor`
    """

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs):
        """Instruments requests module

        Args:
            **kwargs: Optional arguments
                ``tracer_provider``: a TracerProvider, defaults to global
                ``request_hook``: An optional callback that is invoked right after a span is created.
                ``response_hook``: An optional callback which is invoked right before the span is finished processing a response.
                ``excluded_urls``: A string containing a comma-delimited
                    list of regexes used to exclude URLs from tracking
        """
        tracer_provider = kwargs.get("tracer_provider")
        tracer = get_tracer(__name__, __version__, tracer_provider)
        meter_provider = kwargs.get("meter_provider")
        meter = get_meter(
            __name__,
            __version__,
            meter_provider,
        )
        duration_histogram = meter.create_histogram(
            name=MetricInstruments.HTTP_CLIENT_DURATION,
            unit="ms",
            description="measures the duration of the outbound HTTP request",
        )
        _instrument(
            tracer,
            duration_histogram,
            request_hook=kwargs.get("request_hook"),
            response_hook=kwargs.get("response_hook"),
        )

    def _uninstrument(self, **kwargs):
        _uninstrument()

    @staticmethod
    def uninstrument_protocol(protocol):
        """Disables instrumentation on the session object."""
        _uninstrument_from(protocol, restore_as_bound_func=True)
