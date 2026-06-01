from m365_admin_tool.graph import GraphApiError
from m365_admin_tool.outbound import describe_message_trace_error, extract_missing_service_principal_app_id


def test_extract_missing_service_principal_app_id() -> None:
    message = (
        "Service principal-less Authentication failed: the service principal for App ID "
        "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373 was not found."
    )

    assert extract_missing_service_principal_app_id(message) == "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373"


def test_describe_message_trace_error_flags_downstream_app_mismatch() -> None:
    exc = GraphApiError(
        401,
        (
            "Service principal-less Authentication failed: the service principal for App ID "
            "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373 was not found."
        ),
        code="Unauthorized",
    )

    wrapped = describe_message_trace_error(exc, configured_client_id="11111111-1111-1111-1111-111111111111")

    assert "Configured client ID is 11111111-1111-1111-1111-111111111111" in wrapped.message
    assert "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373" in wrapped.message
    assert "not this tool's app registration" in wrapped.message
