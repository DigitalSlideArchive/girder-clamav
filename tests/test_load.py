import pytest

from girder.plugin import loadedPlugins


@pytest.mark.plugin('girder_clamav')
def test_import(server):
    assert 'girder_clamav' in loadedPlugins()
