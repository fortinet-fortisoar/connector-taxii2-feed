from connectors.core.connector import Connector, get_logger, ConnectorError

from .operations import operations, _check_health

logger = get_logger('taxii2-threat-intel-feed')


class TaxiiFeedCon(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation: {}'.format(operation))
        try:
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.error('{}'.format(err))
            raise ConnectorError('{}'.format(err))

    def check_health(self, config):
        return _check_health(config)
