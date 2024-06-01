from identity.identity import PersonIdentityAccess, DeviceIdentityAccess


def create_device_identity() -> DeviceIdentityAccess:
    return DeviceIdentityAccess.create()


def create_person_identity(device_identity: DeviceIdentityAccess) -> PersonIdentityAccess:
    return PersonIdentityAccess.create(device_identity)


def update_identity():
    pass


def delete_identity():
    pass
