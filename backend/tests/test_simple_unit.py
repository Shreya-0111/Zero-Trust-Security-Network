"""
Simple unit test to verify test infrastructure works
"""

import pytest
from unittest.mock import Mock


def test_basic_functionality():
    """Test basic Python functionality"""
    assert 1 + 1 == 2
    assert "hello" == "hello"
    assert [1, 2, 3] == [1, 2, 3]


def test_mock_functionality():
    """Test mock functionality"""
    mock_obj = Mock()
    mock_obj.method.return_value = "test_result"
    
    result = mock_obj.method()
    assert result == "test_result"
    mock_obj.method.assert_called_once()


class TestSimpleClass:
    """Test class structure"""
    
    def test_class_method(self):
        """Test method in class"""
        assert True is True
    
    def test_with_fixture(self):
        """Test with simple data"""
        test_data = {"key": "value"}
        assert test_data["key"] == "value"


def test_exception_handling():
    """Test exception handling"""
    with pytest.raises(ValueError):
        raise ValueError("Test error")


def test_parametrized_test():
    """Test with different inputs"""
    test_cases = [
        (1, 2, 3),
        (5, 5, 10),
        (0, 0, 0)
    ]
    
    for a, b, expected in test_cases:
        assert a + b == expected