from lxml import etree


class Errors():

    @staticmethod
    def badVerb():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'badVerb')
        error.text = 'Value of the verb argument is not a legal OAI-PMH verb, \
                    the verb argument is missing, or the verb argument is repeated.'

        return error

    @staticmethod
    def badArgument():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'badArgument')
        error.text = 'The request includes illegal arguments, is missing required \
                    arguments, includes a repeated argument, or values for arguments have an illegal syntax.'

        return error

    @staticmethod
    def cannotDisseminateFormat():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'cannotDisseminateFormat')
        error.text = 'The metadata format identified by the value given for the metadataPrefix \
                    argument is not supported by the item or by the repository.'

        return error

    @staticmethod
    def idDoesNotExist():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'idDoesNotExist')
        error.text = 'The value of the identifier argument is unknown or illegal in this repository.'

        return error

    @staticmethod
    def badResumptionToken():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'badResumptionToken')
        error.text = 'The value of the resumptionToken argument is invalid or expired.'

        return error

    @staticmethod
    def noRecordsMatch():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'noRecordsMatch')
        error.text = 'The combination of the values of the from, until, set, and metadataPrefix \
                    arguments results in an empty list.'

        return error

    @staticmethod
    def noMetadataFormats():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'noMetadataFormats')
        error.text = 'There are no metadata formats available for the specified item.'

        return error

    @staticmethod
    def noSetHierarchy():
        # Create the root element with the specified verb
        error = etree.Element('error')
        error.set('code', 'noSetHierarchy')
        error.text = 'The repository does not support sets'

        return error
